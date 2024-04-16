# -*- coding: utf-8 -*-
#############################################################################
#
#    Cybrosys Technologies Pvt. Ltd.
#
#    Copyright (C) 2023-TODAY Cybrosys Technologies(<https://www.cybrosys.com>)
#    Author: Cybrosys Techno Solutions(<https://www.cybrosys.com>)
#
#    You can modify it under the terms of the GNU LESSER
#    GENERAL PUBLIC LICENSE (LGPL v3), Version 3.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU LESSER GENERAL PUBLIC LICENSE (LGPL v3) for more details.
#
#    You should have received a copy of the GNU LESSER GENERAL PUBLIC LICENSE
#    (LGPL v3) along with this program.
#    If not, see <http://www.gnu.org/licenses/>.
#
#############################################################################

import json
import logging
import uuid
from odoo import http
from odoo.http import request
from ..oauthlib import oauth2
from ..oauthlib import common
from ..oauth2.validator import OdooValidator
import werkzeug.utils
import werkzeug.wrappers

_client_model = "oauth2.client.model"
_authorization_code_model = "oauth2.authorization.code.model"
_bearer_token_model = "oauth2.bearer.token.model"

_logger = logging.getLogger(__name__)
_list_db = ['plusidea', 'leasing-platform', 'test', 'db']

class RestApi(http.Controller):
    """This is a controller which is used to generate responses based on the
    api requests"""

    @http.route("/test", auth='none', type='http', csrf=False, methods=['GET'])
    def get_test(self, **kw):
        print("Test")
        response = {'message': "Test Test 123"}
        return request.make_response(json.dumps(response), headers={'Content-Type': 'application/json'})

    @http.route('/oauth2lib/loginpage',  auth='none', website=True)
    def index(self, client_id, redirect_uri, response_type, **kw):
        # TODO: Login Page
        http.request.session['oauth_credentials'] = {
                'client_id': client_id, 
                'redirect_uri': redirect_uri,
                'response_type': response_type
            }
        return """
    <t t-set="disable_footer" t-value="True"/>
        <t t-call="web.login_layout">
            <form class="oe_login_form" role="form" method="post" action="/oauth2lib/login">
                <input type="hidden" name="csrf_token" t-att-value="request.csrf_token()"/>
                <div>
                    <h3 t-esc="oauth_client"/>
                    Login Page
                </div>
                <label>username</label>
                <input type="text" name="username" value="admin"/>
                <br/>
                <label>password</label>
                <input type="text" name="password" value="admin"/>
                <br/>
                <!-- <label>db</label>
                <input type="text" name="db" value="admin"/>
                <br/> -->
                <div class="clearfix oe_login_buttons text-center">
                    <button type="submit" class="btn btn-primary">Authorize</button>
                </div>
            </form>
        </t>
"""
        # return http.request.render(
        #         'rest_api_odoo_oauthv5.oauth2_login_form', { })
    
    @http.route(['/oauth2lib/login'], type="http", auth="none", csrf=False,
                methods=['POST'])
    def login(self, **kw):   
        # TODO: Login
        # if request.session.uid:
        #     # Redirect if already logged in and redirect param is present
        #     return http.request.render('rest_api_odoo_oauth.authorization', { })

        username = kw.get('username')
        password = kw.get('password')
        oauth_credentials = http.request.session['oauth_credentials']

        for db in _list_db:
            try:
                _logger.info("auth with db " + db )
                request.session.update(http.get_default_session(), db=db)
                auth = request.session.authenticate(db, username, password)
                # return http.request.render(
                #     'rest_api_odoo_oauthv5.authorization', { })

                _logger.info("auth succes with db " + db )

                # return werkzeug.utils.redirect("/oauth2lib/authorize?client_id="+oauth_credentials['client_id'], code=200)
                # url = "/oauth2lib/authorize?client_id="+oauth_credentials['client_id']+"%26response_type="+oauth_credentials['response_type']+ "%26redirect_uri="+oauth_credentials['redirect_uri']
                url = "/oauth2lib/authorize?client_id="+oauth_credentials['client_id']+"&response_type="+oauth_credentials['response_type']+ "&redirect_uri="+oauth_credentials['redirect_uri']
                
                _logger.info(url)
                return werkzeug.utils.redirect(url, code=200)
            except Exception as e: 
                _logger.error(e)
                _logger.error("db " + db + " not right")

        return "Not found db"

    @http.route(['/oauth2lib/authorize'], type="http", auth="none", csrf=False,
                methods=['GET'])
    def authorize_index(self, client_id, response_type=None, redirect_uri=None, **kw):   
        _logger.info("authorize_index_start: ")
        _logger.info(response_type)
        _logger.info(http.request.httprequest.full_path)
        # TODO: User login?
        # if request.session.uid is None:
        #     # Redirect if already logged in and redirect param is present
        #     return http.request.redirect('web/login?redirect=oauth2lib/authorize?client_id=' + client_id)
        
        # TODO: Database
        # db = request.session.db
        # ensure_db(db=db)

        verify_data = http.request.env[_client_model].sudo().search([])
        verify_data_2 = []
        for rec in verify_data: 
            verify_data_2.append(rec.client_id)
        _logger.info("full database")
        _logger.info(json.dumps(verify_data_2))
        # _logger.info(json.dumps(verify_data))

        # TODO: Check client id
        client = http.request.env['oauth2.client.model'].sudo().search([
            ('client_id', '=', client_id),
        ])

        if not client:
            return "Application dont be registered."
        
        # TODO: Valide request
        oauth2_server = client.get_oauth2_server()

        # Retrieve needed arguments for oauthlib methods
        uri, http_method, body, headers = self._get_request_information()
        _logger.info("Check add new value header")
        try:
            _logger.info("validate_authorization_request: Start  ")
            scopes, credentials = oauth2_server.validate_authorization_request(
                uri, http_method=http_method, body=body, headers=headers)
            _logger.info("credentials and scopes")
            _logger.info(scopes)
            _logger.info(credentials)
            _logger.info("validate_authorization_request: End  ")
            # Store some data
            http.request.session['oauth_scopes'] = scopes
            http.request.session['oauth_credentials'] = {
                'client_id': credentials['client_id'],
                'redirect_uri': credentials['redirect_uri'],
                'response_type': credentials['response_type'],
                'state': credentials['state'],
            }
        except oauth2.FatalClientError as e:
            return e
        except oauth2.OAuth2Error as e:
            return e
        except:
            return e
        
        _logger.info("Client: ")
        oauth_credentials = http.request.session['oauth_credentials']
        _logger.info(json.dumps(oauth_credentials))

        _logger.info("authorize_index_end: ")

        return http.request.render('rest_api_odoo_oauthv5.authorization', {
            'client_id': client.client_id,
            'application_name': client.application_name
            })
    
    @http.route(['/oauth2lib/authorize'], type="http", auth="none", csrf=False,
                methods=['POST'])
    def authorize(self, *args, **kwargs):
        # TODO: Database
        # db = request.session.db
        # ensure_db(db=db)

        # TODO: Get Data from session
        oauth_scopes =  http.request.session['oauth_scopes'] 
        oauth_credentials =  http.request.session['oauth_credentials'] 

        client = http.request.env['oauth2.client.model'].sudo().search([
            ('client_id', '=', oauth_credentials['client_id']),
        ])
     
        # TODO: Create authorization code
        oauth2_server = client.get_oauth2_server()
        uri, http_method, body, headers = self._get_request_information()
        try:
            _logger.info("credentials and scopes")
            _logger.info(oauth_credentials)
            _logger.info(oauth_scopes)
            _logger.info("---------------------------------------- ")
            _logger.info("create_authorization_response: Start  ")
            headers, body, status = oauth2_server.create_authorization_response(
            uri, http_method=http_method, body=body, headers=headers,
            scopes=oauth_scopes, credentials=oauth_credentials)
            _logger.info(headers)
            _logger.info(body)
            _logger.info(status)
            _logger.info("create_authorization_response: End  ")

        except oauth2.FatalClientError as e:
            _logger.info(e)
        except oauth2.OAuth2Error as e:
            _logger.info(e)
        except Exception as e:
            _logger.info(e)
        
        return http.request.render(
                'rest_api_odoo_oauthv5.oauth2_token_form', { })
    
    @http.route(['/oauth2lib/gettoken'], type="http", auth="none", csrf=False,
                methods=['POST'])
    def gettoken(self, *args, **kwargs):
        _logger.info("1")
        oauth_credentials =  http.request.session['oauth_credentials'] 
        _logger.info("2")
        authorization_code = http.request.env[_authorization_code_model].sudo().search([
            ('client_id.client_id', '=', oauth_credentials['client_id']),
            ('code', '=', kwargs.get('code')),
        ])
        _logger.info("3")
        _logger.info(authorization_code.code)
        if not authorization_code:
            return "Access Denied"
        _logger.info("4")
        check_exist_client_id = http.request.env[_client_model].sudo().search([
            ('client_id', '=', oauth_credentials['client_id']),
        ])

        if not check_exist_client_id:
            return "Not Found ClienId"
        oauth2_server = check_exist_client_id.get_oauth2_server()

        uri, http_method, body, headers = self._get_request_information()
        credentials = {'scope': []}

        _logger.info("create_token_response: Start  ")
        headers, body, status = oauth2_server.create_token_response(
            uri, http_method=http_method, body=body, headers=headers,
            credentials=credentials)
        _logger.info(headers)
        _logger.info(body)
        _logger.info(status)
        _logger.info("create_token_response: End  ")
        # return werkzeug.wrappers.BaseResponse(
        #     body, status=status, headers=headers)
        # TODO: Create access token
        # access_token = "Bearer Token = 123"
        # http.request.env['oauth2.bearer.token.model'].sudo().create({
        #     'access_token': access_token,
        # })

        return body

    @http.route(['/oauth2lib/refresh_token'], type="http", auth="none", csrf=False,
                methods=['POST'])
    def refresh_token(self, client_id = None, refresh_token=None, *args, **kwargs):

        check_refresh_token = http.request.env[_bearer_token_model].sudo().search([
            ('refresh_token', '=', refresh_token),
        ])

        _logger.info("3")

        if not check_refresh_token:
            return "Access Denied"
        
        _logger.info(check_refresh_token.access_token)
        _logger.info(check_refresh_token.refresh_token)
        _logger.info("4")
        check_exist_client_id = http.request.env[_client_model].sudo().search([
            ('client_id', '=', client_id),
        ])

        if not check_exist_client_id:
            return "Not Found ClienId"
        
        oauth2_server = check_exist_client_id.get_oauth2_server()

        uri, http_method, body, headers = self._get_request_information()
        credentials = {'scope': []}

        _logger.info("create_token_response: Start  ")
        headers, body, status = oauth2_server.create_token_response(
            uri, http_method=http_method, body=body, headers=headers,
            credentials=credentials)
        
        _logger.info(headers)
        _logger.info(body)
        _logger.info(status)
        _logger.info("create_token_response: End  ")
        # return werkzeug.wrappers.BaseResponse(
        #     body, status=status, headers=headers)
        # TODO: Create access token
        # access_token = "Bearer Token = 123"
        # http.request.env['oauth2.bearer.token.model'].sudo().create({
        #     'access_token': access_token,
        # })

        return body
    

    @http.route(['/oauth2lib/getInfo'], type="http", auth="none", csrf=False,
                methods=['GET'])
    def getInfo(self, *args, **kwargs):
        
        _logger.info("1")
        access_token = http.request.httprequest.headers['Authorization']
        _logger.info("2")
        _logger.info(access_token)
        check_access_token = http.request.env['oauth2.bearer.token.model'].sudo().search([
            ('access_token', '=', access_token),
        ])
        _logger.info("3")
        # data = http.request.env['res.user'].sudo().search([ ])
        current_user = request.env['res.partner'].sudo().search([])
        _logger.info("4")
        if not check_access_token:
            return "Access Denied"
        _logger.info("5")
        _logger.info(current_user)
        user = []
        for rec in current_user: 
            user.append(rec.name)
            user.append(rec.name)
        _logger.info("6")
        return request.make_response(json.dumps(user), headers={'Content-Type': 'application/json'})
    
    def _get_request_information(self):
        """ Retrieve needed arguments for oauthlib methods """
        uri = http.request.httprequest.base_url
        http_method = http.request.httprequest.method
        body = common.urlencode(
            http.request.httprequest.values.items())
        headers = http.request.httprequest.headers
        return uri, http_method, body, headers
    
