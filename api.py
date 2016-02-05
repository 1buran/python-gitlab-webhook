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
import json

import logging

import falcon

import yaml


conf = {}

with open('config.yml') as config_file:
    conf.update(yaml.load(config_file))


logging.basicConfig(**conf['log_settings'])


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
        self.log = logging.getLogger('GitLab')

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
        resp.status = falcon.HTTP_201


gitlab_webhook_receiver = GitLabWebHookReceiver()
api = application = falcon.API(middleware=[
    AuthMiddleware(), RequireJSON(), JSONTranslator()])
api.add_route('/gitlab/webhook', gitlab_webhook_receiver)

if __name__ == '__main__':

    from wsgiref import simple_server

    httpd = simple_server.make_server(
        conf['listen_address'], conf['listen_port'], api)
    httpd.serve_forever()
