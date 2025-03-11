# -*- coding: utf-8 -*-

# Copyright (c) 2014 CoNWeT Lab., Universidad Politécnica de Madrid
# Copyright (c) 2018 Future Internet Consulting and Development Solutions S.L.

# This file is part of OAuth2 CKAN Extension.

# OAuth2 CKAN Extension is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# OAuth2 CKAN Extension is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.

# You should have received a copy of the GNU Affero General Public License
# along with OAuth2 CKAN Extension.  If not, see <http://www.gnu.org/licenses/>.

from __future__ import unicode_literals

import logging
import oauth2
import os

from functools import partial
from ckan import plugins
from ckan.common import g
from ckan.plugins import toolkit
from urllib.parse import urlparse
from flask import Blueprint, redirect

log = logging.getLogger(__name__)


def _no_permissions(context, msg):
    user = context['user']
    return {'success': False, 'msg': msg.format(user=user)}


@toolkit.auth_sysadmins_check
def user_create(context, data_dict):
    msg = toolkit._('Users cannot be created.')
    return _no_permissions(context, msg)


@toolkit.auth_sysadmins_check
def user_update(context, data_dict):
    msg = toolkit._('Users cannot be edited.')
    return _no_permissions(context, msg)


@toolkit.auth_sysadmins_check
def user_reset(context, data_dict):
    msg = toolkit._('Users cannot reset passwords.')
    return _no_permissions(context, msg)


@toolkit.auth_sysadmins_check
def request_reset(context, data_dict):
    msg = toolkit._('Users cannot reset passwords.')
    return _no_permissions(context, msg)


def _get_previous_page(default_page):
    if 'came_from' not in toolkit.request.params:
        came_from_url = toolkit.request.headers.get('Referer', default_page)
    else:
        came_from_url = toolkit.request.params.get('came_from', default_page)

    came_from_url_parsed = urlparse(came_from_url)

    # Avoid redirecting users to external hosts
    if came_from_url_parsed.netloc != '' and came_from_url_parsed.netloc != toolkit.request.host:
        came_from_url = default_page

    # When a user is being logged and REFERER == HOME or LOGOUT_PAGE
    # he/she must be redirected to the dashboard
    pages = ['/', '/user/logged_out_redirect']
    if came_from_url_parsed.path in pages:
        came_from_url = default_page

    return came_from_url


# Flask views for OAuth2 login and callback
def login():
    """
    Flask view for login using OAuth2
    """
    from ckanext.oauth2 import constants
    log.debug('login')

    # Log in attempts are fired when the user is not logged in and they click
    # on the log in button

    # Get the page where the user was when the login attempt was fired
    # When the user is not logged in, he/she should be redirected to the dashboard when
    # the system cannot get the previous page
    came_from_url = _get_previous_page(constants.INITIAL_PAGE)

    oauth2_helper = oauth2.OAuth2Helper()
    return oauth2_helper.challenge(came_from_url)


def callback():
    """
    Flask view for OAuth2 callback
    """
    from flask import flash, request
    from ckan.common import session
    import ckan.lib.helpers as helpers
    from ckanext.oauth2 import constants

    oauth2_helper = oauth2.OAuth2Helper()
    try:
        token = oauth2_helper.get_token()
        user_name = oauth2_helper.identify(token)
        oauth2_helper.remember(user_name)
        oauth2_helper.update_token(user_name, token)
        return oauth2_helper.redirect_from_callback()
    except Exception as e:
        session.save()

        # If the callback is called with an error, we must show the message
        error_description = request.args.get('error_description')
        if not error_description:
            if getattr(e, 'message', None):
                error_description = e.message
            elif hasattr(e, 'description') and e.description:
                error_description = e.description
            elif hasattr(e, 'error') and e.error:
                error_description = e.error
            else:
                error_description = type(e).__name__

        redirect_url = oauth2.get_came_from(request.args.get('state'))
        redirect_url = '/' if redirect_url == constants.INITIAL_PAGE else redirect_url
        flash(error_description, 'error')
        return redirect(redirect_url)


class OAuth2Plugin(plugins.SingletonPlugin):

    plugins.implements(plugins.IAuthenticator, inherit=True)
    plugins.implements(plugins.IAuthFunctions, inherit=True)
    plugins.implements(plugins.IBlueprint)
    plugins.implements(plugins.IConfigurer)

    def __init__(self, name=None):
        '''Store the OAuth 2 client configuration'''
        log.debug('Init OAuth2 extension')

        self.oauth2helper = oauth2.OAuth2Helper()
        
        # Store these for use in get_blueprint
        self.register_url = None
        self.reset_url = None
        self.edit_url = None
        self.authorization_header = None

    def get_blueprint(self):
        """
        Return a Flask Blueprint object to be registered by the app.
        """
        # Create Blueprint for plugin
        blueprint = Blueprint('oauth2', __name__)
        
        # Add plugin url rules to Blueprint object
        blueprint.add_url_rule('/user/login', 
                              'login',
                              login, 
                              methods=['GET', 'POST'])
        
        blueprint.add_url_rule('/oauth2/callback',
                              'callback',
                              callback,
                              methods=['GET'])
        
        # Handle redirects that were previously done in before_map
        if self.register_url:
            @blueprint.route('/user/register')
            def register_redirect():
                return redirect(self.register_url)
                
        if self.reset_url:
            @blueprint.route('/user/reset')
            def reset_redirect():
                return redirect(self.reset_url)
                
        if self.edit_url:
            @blueprint.route('/user/edit/<user>')
            def edit_redirect(user):
                # Format the URL with the user parameter
                formatted_url = self.edit_url
                if '{user}' in self.edit_url:
                    formatted_url = self.edit_url.format(user=user)
                return redirect(formatted_url)
        
        return blueprint

    def identify(self):
        log.debug('identify')

        def _refresh_and_save_token(user_name):
            new_token = self.oauth2helper.refresh_token(user_name)
            if new_token:
                toolkit.c.usertoken = new_token

        environ = toolkit.request.environ
        apikey = toolkit.request.headers.get(self.authorization_header, '')
        user_name = None

        if self.authorization_header == "authorization":
            if apikey.startswith('Bearer '):
                apikey = apikey[7:].strip()
            else:
                apikey = ''

        # This API Key is not the one of CKAN, it's the one provided by the OAuth2 Service
        if apikey:
            try:
                token = {'access_token': apikey}
                user_name = self.oauth2helper.identify(token)
            except Exception:
                pass

        # If the authentication via API fails, we can still log in the user using session.
        if user_name is None and 'repoze.who.identity' in environ:
            user_name = environ['repoze.who.identity']['repoze.who.userid']
            log.info('User %s logged using session' % user_name)

        # If we have been able to log in the user (via API or Session)
        if user_name:
            g.user = user_name
            toolkit.c.user = user_name
            toolkit.c.usertoken = self.oauth2helper.get_stored_token(user_name)
            toolkit.c.usertoken_refresh = partial(_refresh_and_save_token, user_name)
        else:
            g.user = None
            log.warn('The user is not currently logged...')

    def get_auth_functions(self):
        # we need to prevent some actions being authorized.
        return {
            'user_create': user_create,
            'user_update': user_update,
            'user_reset': user_reset,
            'request_reset': request_reset
        }

    def update_config(self, config):
        # Update our configuration
        self.register_url = os.environ.get("CKAN_OAUTH2_REGISTER_URL", config.get('ckan.oauth2.register_url', None))
        self.reset_url = os.environ.get("CKAN_OAUTH2_RESET_URL", config.get('ckan.oauth2.reset_url', None))
        self.edit_url = os.environ.get("CKAN_OAUTH2_EDIT_URL", config.get('ckan.oauth2.edit_url', None))
        self.authorization_header = os.environ.get("CKAN_OAUTH2_AUTHORIZATION_HEADER", config.get('ckan.oauth2.authorization_header', 'Authorization')).lower()

        # Add this plugin's templates dir to CKAN's extra_template_paths, so
        # that CKAN will use this plugin's custom templates.
        plugins.toolkit.add_template_directory(config, 'templates')

