# Imports from python standard library
from base64 import b64decode
from datetime import datetime, timezone
from urllib.request import urlopen

import asyncio
import pwd
import subprocess

from saml2 import BINDING_HTTP_POST
from saml2 import BINDING_HTTP_REDIRECT
from saml2 import entity
from saml2.client import Saml2Client
from saml2.config import Config as Saml2Config

# Imports to work with JupyterHub
from jupyterhub.auth import Authenticator
from jupyterhub.utils import maybe_future
from jupyterhub.handlers.base import BaseHandler
from jupyterhub.handlers.login import LoginHandler, LogoutHandler
from tornado import gen, web
from traitlets import Unicode, Bool
from jinja2 import Template

# Imports for me
from lxml import etree
import pytz
from signxml import XMLVerifier

class SAMLAuthenticator(Authenticator):
    metadata_filepath = Unicode(
        default_value='',
        allow_none=True,
        config=True,
        help='''
        A filepath to the location of the SAML IdP metadata. This is the most preferable
        option for presenting an IdP's metadata to the authenticator.
        '''
    )
    metadata_content = Unicode(
        default_value='',
        allow_none=True,
        config=True,
        help='''
        A fully-inlined version of the SAML IdP metadata. Mostly provided for testing,
        but if you want to use this for a "production-type" system, I'm not going to
        judge. This is preferred above getting metadata from a web-request, but not
        preferred above getting the metadata from a file.
        '''
    )
    metadata_url = Unicode(
        default_value='',
        allow_none=True,
        config=True,
        help='''
        A URL where the SAML Authenticator can find metadata for the SAML IdP. This is
        the least preferable method of providing the SAML IdP metadata to the
        authenticator, as it is both slow and vulnerable to Man in the Middle attacks,
        including DNS poisoning.
        '''
    )
    shutdown_on_logout = Bool(
        default_value=False,
        allow_none=False,
        config=True,
        help='''
        If you would like to shutdown user servers on logout, you can enable this
        behavior with:

        c.SAMLAuthenticator.shutdown_on_logout = True

        Be careful with this setting because logging out one browser does not mean
        the user is no longer actively using their server from another machine.

        It is a little odd to have this property on the Authenticator object, but
        (for internal-detail-reasons) since we need to hand-craft the LogoutHandler
        class, this should be on the Authenticator.
        '''
    )
    entity_id = Unicode(
        default_value='',
        allow_none=True,
        config=True,
        help='''
        The entity id for this specific JupyterHub instance. If
        populated, this will be included in the SP metadata as
        the entity id. If this is not populated, the entity will
        populate as the protocol, host, and port of the request
        to get the SAML Metadata.

        Note that if the JupyterHub server will be behind a
        proxy, this should be populated as the protocol, host,
        and port where the server can be reached. For example,
        if the JupyterHub server should be reached at
        10.0.31.2:8000, this should be populated as
        'https://10.0.31.2:8000'
        '''
    )
    acs_endpoint_url = Unicode(
        default_value='',
        allow_none=True,
        config=True,
        help='''
        The access consumer endpoint url for this specific
        JupyterHub instance. If populated, this will be
        included in the SP metadata as the acs endpoint
        location. If populated, this field MUST tell the
        SAML IdP to post to the ip address and port the
        JupyterHub is running on concatenated to
        "/hub/login". For example, if the server were
        running on 10.0.31.2:8000, this value should be
        'https://10.0.31.2:8000/hub/login'. It is necessary
        to populate this field if the ACS Endpoint is
        significantly different from the entity id.
        If this is not populated, the entity location
        will populate as the entity id concatenated
        to '/hub/login'.
        '''
    )

    @gen.coroutine
    def authenticate(self, handler, data):
        saml_client = self._get_saml_client()
        authn_response = saml_client.parse_authn_request_response(data['SAMLResponse'], entity.BINDING_HTTP_POST)
        authn_response.get_identity()
        user_info = authn_response.get_subject()
        username = user_info.text
    
        username = self.normalize_username(username)
        if self.validate_username(username) and self.check_blacklist(username) and self.check_whitelist(username):
            return username

        # Failed to validate username or failed list check
        self.log.error('Failed to validate username or failed list check')
        return None

    def _get_saml_client(self):
        settings = {
            'entityid': self.entity_id,
            'metadata': {
            },
            'service': {
                'sp': {
                    'endpoints': {
                        'assertion_consumer_service': [
                            (self.acs_endpoint_url, BINDING_HTTP_REDIRECT),
                            (self.acs_endpoint_url, BINDING_HTTP_POST),
                        ],
                    },
                    'allow_unsolicited': True,
                    'authn_requests_signed': False,
                    'logout_requests_signed': True,
                    'want_assertions_signed': True,
                    'want_response_signed': False,
                },
            },
            'allow_unknown_attributes': True,
        }
        if self.metadata_filepath:
            settings['metadata']['local'] = [self.metadata_filepath]
        if self.metadata_content:
            settings['metadata']['inline'] = [self.metadata_content]
        if self.metadata_url:
            settings['metadata']['remote'] = {'url': self.metadata_url}

        config = Saml2Config()
        config.load(settings)
        saml_client = Saml2Client(config=config)
        return saml_client

    def get_handlers(authenticator_self, app):

        class SAMLLoginHandler(LoginHandler):

            def check_xsrf_cookie(self):
                return

            async def get(login_handler_self):
                login_handler_self.log.info('Starting SP-initiated SAML Login')
                saml_client = authenticator_self._get_saml_client()
                reqid, info = saml_client.prepare_for_authenticate()
                redirect_url = None
                for key, value in info['headers']:
                    if key == 'Location':
                        redirect_url = value
                login_handler_self.redirect(redirect_url, permanent=False)

        class SAMLLogoutHandler(LogoutHandler):
            # TODO: When the time is right to force users onto JupyterHub 1.0.0,
            # refactor this.
            async def _shutdown_servers(self, user):
                active_servers = [
                    name
                    for (name, spawner) in user.spawners.items()
                    if spawner.active and not spawner.pending
                ]
                if active_servers:
                    self.log.debug("Shutting down %s's servers", user.name)
                    futures = []
                    for server_name in active_servers:
                        futures.append(maybe_future(self.stop_single_user(user, server_name)))
                    await asyncio.gather(*futures)

            def _backend_logout_cleanup(self, name):
                self.log.info("User logged out: %s", name)
                self.clear_login_cookie()
                self.statsd.incr('logout')

            async def _shutdown_servers_and_backend_cleanup(self):
                user = self.current_user
                if user:
                    await self._shutdown_servers(user)

            async def get(logout_handler_self):
                if authenticator_self.shutdown_on_logout:
                    logout_handler_self.log.debug('Shutting down servers during SAML Logout')
                    await logout_handler_self._shutdown_servers_and_backend_cleanup()

                if logout_handler_self.current_user:
                    logout_handler_self._backend_logout_cleanup(logout_handler_self.current_user.name)

                html = logout_handler_self.render_template('logout.html', sync=True)
                logout_handler_self.finish(html)


        return [('/login', SAMLLoginHandler),
                ('/hub/login', SAMLLoginHandler),
                ('/logout', SAMLLogoutHandler),
                ('/hub/logout', SAMLLogoutHandler),
        ]
