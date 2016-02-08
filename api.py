"""GitLab Webhook receiver.

The goal: receive web hook request from GtLab, run project tests,
respond with comment of status.

Requirements:
    - python 3.x
    - falcon (http://falconframework.org/)
    - mongoengine (http://mongoengine.org/)
    - pyyaml (http://pyyaml.org/)

Setup:
    $ pip install -U pip setuptools
    $ pip install -U cython
    $ pip install -U falcon
    $ pip install -U pyyaml mongoengine
"""
import os
import re
import json
import time
import logging
import logging.config
import falcon
import yaml
import requests
from multiprocessing import Queue

conf = {}
merge_requests_queue = Queue()

with open('config.yml') as config_file:
    conf.update(yaml.load(config_file))
    conf['validate_regex'] = re.compile(conf['validate_regex'])


logging.config.dictConfig(conf['log_settings'])

re_gitlab_url = re.compile(r'https?://[\w.]+/')


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

    def __init__(self, repo_url, project_id, iid):
        """Standart init method."""
        self.token = conf['gitlab_auth_token']
        self.session = requests.Session()
        self.session.headers.update({'PRIVATE-TOKEN': self.token})
        self.repo_url = repo_url
        self.project_id = project_id
        self.iid = iid
        self.api_url = re_gitlab_url.match(self.repo_url).group(0) + 'api/v3'
        self.log = logging.getLogger(self.__class__.__name__)

    def get_merge_request_commits(self):
        """Get merge request."""
        try:
            response = self.session.get(
                '{api_url}/projects/{project_id}/merge_request/{iid}/commits'
                .format(api_url=self.api_url, project_id=self.project_id,
                        iid=self.iid)
            )
        except Exception as er:
            self.log.error(er)

        if response.status_code != 200:
            self.log.warning('http response status code: %d',
                             response.status_code)
        return response.json()

    def validate_merge_request_commits(self):
        """Validate merge requests commits."""
        for commit in self.get_merge_request_commits():
            if not conf['validate_regex'].match(commit['message']):
                return False, commit['message']
        return True, ''

    def comment_merg_request(self, msg):
        """Comment merge request."""
        try:
            response = self.session.post(
                '{api_url}/projects/{project_id}/merge_request/{iid}/comments'
                .format(api_url=self.api_url, project_id=self.project_id,
                        iid=self.iid),
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
                '{api_url}/projects/{project_id}/merge_request/{iid}'
                .format(api_url=self.api_url, project_id=self.project_id,
                        iid=self.iid),
                data={'state_event': 'close'}
            )
        except Exception as er:
            self.log.error(er)

        if response.status_code != 200:
            self.log.warning('http response status code: %d',
                             response.status_code)


def process_merge_request():
    """Process each merge request.

    This is blocking operation: we awaiting for a new merge requst paload in
    queue, so this is function should be run in separate process.
    """
    item = merge_requests_queue.get(block=True)
    gitlab_api = GitLabAPI(
        repo_url=item['repository']['homepage'],
        project_id=item['object_attributes']['target_project_id'],
        iid=item['object_attributes']['iid']
    )
    if conf['validate_commit_messages']:
        valid, info = gitlab_api.validate_merge_request_commits()
        if not valid:
            msg = 'Received commit has invalid message: "%s"' % info
            gitlab_api.comment_merg_request(msg)
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
