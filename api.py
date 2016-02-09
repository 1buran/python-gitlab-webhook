"""GitLab Webhook receiver.

The goal: receive web hook request from GtLab, run project tests,
respond with comment of status.

Requirements:
    - python 3.x
    - falcon (http://falconframework.org/)
    - mongoengine (http://mongoengine.org/)
    - pyyaml (http://pyyaml.org/)

Setup:
    - install system packages:
        $ sudo apt-get install python-virtualenv
    - create virtual environment, enable it and install requirements:
        $ pip install -U pip setuptools
        $ pip install -U cython
        $ pip install -U falcon
        $ pip install -U pyyaml mongoengine requests
"""
import os
import os.path
import re
import subprocess
import json
import time
import logging
import logging.config
import falcon
import yaml
import requests
import tempfile
from multiprocessing import Queue

conf = {}
merge_requests_queue = Queue()

with open('config.yml') as config_file:
    conf.update(yaml.load(config_file))
    conf['validate_regex'] = re.compile(conf['validate_regex'])


logging.config.dictConfig(conf['log_settings'])

re_gitlab_url = re.compile(r'https?://[\w.]+/')
re_repo_work_dir = re.compile(r'/([\w.-]+).git$')
install_dir = os.path.dirname(os.path.abspath(__file__))


class AuthMiddleware:
    """Simple auth by token."""

    def process_request(self, req, resp):
        """Process each request."""
        token = req.get_param('token', required=True)
        if token != conf['access_key']:
            raise falcon.HTTPUnauthorized(
                'Authentication Required',
                'Please provide auth token as part of request.')


class RequireJSON:
    """Check incoming requests type."""

    error_msg = falcon.HTTPNotAcceptable(
        'This API only supports responses encoded as JSON.',
        href='http://docs.examples.com/api/json')

    def process_request(self, req, resp):
        """Process each request."""
        if not req.client_accepts_json:
            raise self.error_msg

        if req.method in ('POST', 'PUT'):
            if 'application/json' not in req.content_type:
                raise self.error_msg


class JSONTranslator:
    """Process JSON of incoming requests."""

    def process_request(self, req, resp):
        """Process each request."""
        if req.content_length in (None, 0):
            return

        body = req.stream.read()
        if not body:
            raise falcon.HTTPBadRequest('Empty request body',
                                        'A valid JSON document is required.')
        try:
            req.context['payload'] = json.loads(body.decode('utf-8'))
        except Exception as er:
            raise falcon.HTTPError(falcon.HTTP_753, 'Malformed JSON', str(er))


def max_body(limit):
    """Max body size hook."""
    def hook(req, resp, resource, params):
        length = req.content_length
        if length is not None and length > limit:
            msg = ('The size of the request is too large. The body must not '
                   'exceed ' + str(limit) + ' bytes in length.')

            raise falcon.HTTPRequestEntityTooLarge(
                'Request body is too large', msg)
    return hook


def run_cmd(cmd):
    """Run command in shell."""
    try:
        output = subprocess.check_output(
            cmd, shell=True, stderr=subprocess.STDOUT,
            universal_newlines=True)
    except subprocess.CalledProcessError as er:
        return False, er.output
    else:
        return True, output


class GitLabWebHookReceiver:
    """GitLab Web hook receiver."""

    def __init__(self):
        """Standart init method."""
        self.log = logging.getLogger(self.__class__.__name__)

    @falcon.before(max_body(1024 * 1024))
    def on_post(self, req, resp):
        """Process POST requet from GitLab."""
        try:
            payload = req.context['payload']
        except KeyError:
            raise falcon.HTTPBadRequest(
                'Missing thing',
                'A thing must be submitted in the request body.')
        self.log.debug('received data: %s', payload, extra=req.env)
        merge_requests_queue.put_nowait(payload)
        resp.status = falcon.HTTP_201


class GitLabAPI:
    """Simple class for using GitLab API."""

    def __init__(self, repo_url, clone_url, project_id, branch, mr_id):
        """Standart init method."""
        self.token = conf['gitlab_auth_token']
        self.session = requests.Session()
        self.session.headers.update({'PRIVATE-TOKEN': self.token})
        self.repo_url = repo_url
        self.clone_url = clone_url
        self.project_id = project_id
        self.branch = branch
        self.mr_id = mr_id
        self.api_url = re_gitlab_url.match(self.repo_url).group(0) + 'api/v3'
        self.log = logging.getLogger(self.__class__.__name__)
        self.workdir = None
        self.repo_dir = None

    def get_merge_request_commits(self):
        """Get merge request."""
        try:
            response = self.session.get(
                '{api_url}/projects/{project_id}/merge_request/{mr_id}/commits'
                .format(api_url=self.api_url, project_id=self.project_id,
                        mr_id=self.mr_id)
            )
        except Exception as er:
            self.log.error(er)

        if response.status_code != 200:
            self.log.warning('http response status code: %d',
                             response.status_code)
        return response.json()

    def get_merge_request_changes(self):
        """Get merge request changes."""
        url = '{api_url}/projects/{project_id}/merge_request/{mr_id}/changes'\
            .format(api_url=self.api_url, project_id=self.project_id,
                    mr_id=self.mr_id)
        try:
            response = self.session.get(url)
        except Exception as er:
            self.log.error(er)

        if response.status_code != 200:
            self.log.warning('http response status code: %d, url: %s',
                             response.status_code, url)
        return response.json()

    def validate_merge_request_commits(self):
        """Validate merge requests commits."""
        bad_messages = []
        for commit in self.get_merge_request_commits():
            if not conf['validate_regex'].match(commit['message']):
                bad_messages.append(commit['message'])
        return len(bad_messages) == 0, '\n'.join(bad_messages)

    def run_commits_messages_validator(self):
        """Run self.validate_merge_request_commits."""
        valid, info = self.validate_merge_request_commits()
        if not valid:
            msg = 'Merge request commits have invalid messages:\n'
            msg += '<pre>%s</pre>' % info
            self.comment_merge_request(msg)
        return valid

    def comment_merge_request(self, msg):
        """Comment merge request."""
        url = '{api_url}/projects/{project_id}/merge_request/{mr_id}/comments'\
            .format(api_url=self.api_url, project_id=self.project_id,
                    mr_id=self.mr_id)
        try:
            response = self.session.post(
                url,
                data={'note': msg}
            )
        except Exception as er:
            self.log.error(er)

        if response.status_code != 200:
            self.log.warning('http response status code: %d',
                             response.status_code)

    def close_merge_request(self):
        """Close merge request."""
        try:
            response = self.session.put(
                '{api_url}/projects/{project_id}/merge_request/{mr_id}'
                .format(api_url=self.api_url, project_id=self.project_id,
                        mr_id=self.mr_id),
                data={'state_event': 'close'}
            )
        except Exception as er:
            self.log.error(er)

        if response.status_code != 200:
            self.log.warning('http response status code: %d',
                             response.status_code)

    def prepare_workdir(self):
        """Clone upstream repo."""
        os.chdir(install_dir)

        if os.path.isdir(conf['git_workdir']):
            found = re_repo_work_dir.search(self.clone_url)
            if found:
                self.workdir = found.group(1)
            else:
                self.log.error(
                    'bogus Git repo URL %s', self.clone_url)
                return False
        else:
            self.log.error(
                'directory %s does not exist', conf['git_workdir'])
            return False

        self.repo_dir = os.path.join(conf['git_workdir'], self.workdir)

        if os.path.isdir(self.repo_dir):
            # clean up git workdir, reset changes, fetch updates
            os.chdir(self.repo_dir)
            ok, output = run_cmd(
                'git checkout -- . && git clean -fd && git pull && '
                'git checkout {branch}'.format(branch=self.branch))
            if not ok:
                self.log.error(output)
        else:
            # initialize new repo dir: clone repo
            os.chdir(conf['git_workdir'])
            cmd = 'git clone -q {clone_url} && cd {workdir} && \
                git checkout {branch}'.format(
                clone_url=self.clone_url, branch=self.branch,
                workdir=self.workdir)
            ok, output = run_cmd(cmd)
            if not ok:
                self.log.error(
                    'can not clone repo %s into %s <%s>',
                    self.clone_url, self.repo_dir, output)
                return False
        self.apply_patch()
        return True

    def run_test_cmd(self):
        """Run test command."""
        ok, output = run_cmd(conf['test_cmd'])
        if not ok:
            msg = 'Test command failed, '
            msg += 'please checkout output of **%s**:\n' % conf['test_cmd']
            msg += '<pre>%s</pre>' % output
            self.log.warning(msg)
            self.comment_merge_request(msg)
        return ok

    def apply_patch(self):
        """Apply patch."""
        diff = ''
        for change in self.get_merge_request_changes()['changes']:
            diff += change['diff']
        with tempfile.NamedTemporaryFile(
                'w', encoding='utf-8', delete=False) as f:
            f.write(diff)
        ok, output = run_cmd('patch -p 1 < {file}'.format(file=f.name))
        if not ok:
            self.log.error(output)
        os.unlink(f.name)


def process_merge_request():
    """Process each merge request.

    This is blocking operation: we awaiting for a new merge requst payload
    in queue, so this is function should be run in separate process.
    """
    item = merge_requests_queue.get(block=True)
    if item['object_attributes']['state'] in ('reopened', 'opened'):
        gitlab_api = GitLabAPI(
            repo_url=item['repository']['homepage'],
            clone_url=item['repository']['url'],
            project_id=item['object_attributes']['target_project_id'],
            branch=item['object_attributes']['target_branch'],
            mr_id=item['object_attributes']['id']
        )
        tests_results = [True]
        if conf['validate_commit_messages']:
            tests_results.append(gitlab_api.run_commits_messages_validator())
        if conf['run_tests']:
            done = gitlab_api.prepare_workdir()
            if done:
                tests_results.append(gitlab_api.run_test_cmd())
        if not all(tests_results):
            gitlab_api.close_merge_request()

gitlab_webhook_receiver = GitLabWebHookReceiver()
api = application = falcon.API(middleware=[
    AuthMiddleware(), RequireJSON(), JSONTranslator()])
api.add_route('/gitlab/webhook', gitlab_webhook_receiver)

if __name__ == '__main__':

    pid = os.fork()
    if pid:
        # parent process
        from wsgiref import simple_server

        httpd = simple_server.make_server(
            conf['listen_address'], conf['listen_port'], api)
        httpd.serve_forever()
    else:
        # child process
        while True:
            process_merge_request()
            time.sleep(2)
