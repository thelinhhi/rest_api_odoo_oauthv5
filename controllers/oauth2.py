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
from odoo import http
from odoo.http import request
import werkzeug.utils
import werkzeug.wrappers
from ..oauthlib import oauth2
from ..oauthlib import common
from ..oauth2.validator import OdooValidator
_logger = logging.getLogger(__name__)


class Oauth2Controller(http.Controller):
    """This is a controller which is used to generate responses based on the
    api requests"""

    @http.route(['/oauth2lib/login'], type="http", auth="none", csrf=False,
                methods=['POST'])
    def login(self, **kw):   
        # TODO: Login
        # if request.session.uid:
        #     # Redirect if already logged in and redirect param is present
        #     return http.request.render('rest_api_odoo_oauth.authorization', { })

        username = kw.get('username')
        password = kw.get('password')
        db = kw.get('db')
        db1 = request.session.db
        print("123")
        print(db1)
        try:
            request.session.update(http.get_default_session(), db=db)
            auth = request.session.authenticate(db, username, password)
            return http.request.render(
                'rest_api_odoo_oauth.authorization', { })
        
        except Exception as e: 
            print(e)
            return "WrongUSerNamePasswor"
        
    @http.route('/oauth2lib/loginpage',  auth='none', website=True)
    def index(self, **kw):
        # TODO: Login Page
        return http.request.render(
                'rest_api_odoo_oauth.oauth2_login_form', { })
    
    @http.route('/oauth2/loginpage',  auth='none', website=True)
    def index(self, **kw):
        # TODO: Login Page
        return """
   <t t-set="disable_footer" t-value="True"/>
        <t t-call="web.login_layout">
            <form class="oe_login_form" role="form" method="post" action="/oauth2/login">
                <input type="hidden" name="csrf_token" t-att-value="request.csrf_token()"/>
                <div>
                    <h3 t-esc="oauth_client"/>
                    Login Page
                </div>
                <label>username</label>
                <input type="text" name="username" t-value="admin"/>
                <br/>
                <label>password</label>
                <input type="text" name="password" t-value="admin"/>
                <br/>
                <div class="clearfix oe_login_buttons text-center">
                    <button type="submit" class="btn btn-primary">Authorize</button>
                </div>
            </form>
        </t>
"""

    @http.route(['/oauth2/login'], type="http", auth="none", csrf=False,
                methods=['POST'])
    def login(self, **kw):   
        # TODO: Login
        username = kw.get('username')
        password = kw.get('password')
        db = "mydb_2"
        try:
            request.session.update(http.get_default_session(), db=db)
            auth = request.session.authenticate(db, username, password)
            return """

      <t t-set="disable_footer" t-value="True"/>
        <t t-call="web.login_layout">
            <form class="oe_login_form" role="form" method="post" action="/oauth2/authorize">
                <input type="hidden" name="csrf_token" t-att-value="request.csrf_token()"/>
                <div>
                    <h3 t-esc="oauth_client"/>
                    This application would like to access these resources :
                </div>
                <input type="text" name="client_id"/>
                <div class="clearfix oe_login_buttons text-center">
                    <button type="submit" class="btn btn-primary">Authorize</button>
                </div>
            </form>
        </t>
"""
        except Exception as e: 
            print(e)
            return "WrongUSerNamePasswor"
        

    @http.route(['/oauth2/authorize'], type="http", auth="none", csrf=False,
                methods=['POST'])
    def authorize(self, *args, **kwargs):

        client_id = kwargs.get('client_id')
        check_exist_client_id = http.request.env['oauth2.client.model'].sudo().search([
            ('client_id', '=', kwargs.get('client_id')),
        ])

        if not check_exist_client_id:
            return "Not Found ClienId"
        
        # TODO: Create authorization code
        code = "123"
        http.request.env['oauth2.authorization.code.model'].sudo().create({
            'code': code,
            'client_id': client_id,
            'user_id': request.env.user
            # 'redirect_uri_id': redirect_uri.id,
            # 'scope_ids': [(6, 0, request.client.scope_ids.filtered(
            #     lambda record: record.code in request.scopes).ids)],
        })

        return """
        <t t-call="web.login_layout">
            <form class="oe_login_form" role="form" method="post" action="/oauth2/gettoken">
                <input type="hidden" name="csrf_token" t-att-value="request.csrf_token()"/>
                <div>
                    <h3 t-esc="oauth_client"/>
                    Get Token
                </div>
                <input type="text" name="client_id"/>
                <input type="text" name="code"/>
                <div class="clearfix oe_login_buttons text-center">
                    <button type="submit" class="btn btn-primary">Authorize</button>
                </div>
            </form>
        </t>
"""

    @http.route(['/oauth2/gettoken'], type="http", auth="none", csrf=False,
                methods=['POST'])
    def gettoken(self, *args, **kwargs):
        
        code = http.request.env['oauth2.authorization.code.model'].sudo().search([
            ('client_id', '=', kwargs.get('client_id')),
            ('code', '=', kwargs.get('code')),
        ])

        if not code:
            return "Not Found ClienId"
        
        # TODO: Create access token
        access_token = "Bearer Token = 123"
        http.request.env['oauth2.bearer.token.model'].sudo().create({
            'access_token': access_token,
        })

        return access_token

  
    @http.route(['/oauth2/getInfo'], type="http", auth="none", csrf=False,
                methods=['GET'])
    def getInfo(self, *args, **kwargs):
        
        access_token = http.request.httprequest.headers['Authorization']
        print(access_token)
        check_access_token = http.request.env['oauth2.bearer.token.model'].sudo().search([
            ('access_token', '=', access_token),
        ])

        if not check_access_token:
            return "Access Denied"
        
  
        return "OK"
    
    def _get_request_information(self):
        """ Retrieve needed arguments for oauthlib methods """
        uri = http.request.httprequest.base_url
        http_method = http.request.httprequest.method
        body = common.urlencode(
            http.request.httprequest.values.items())
        headers = http.request.httprequest.headers

        return uri, http_method, body, headers