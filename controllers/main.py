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

_logger = logging.getLogger(__name__)


class RestApi(http.Controller):
    """This is a controller which is used to generate responses based on the
    api requests"""

    @http.route(['/signin'], type="http", auth="none", csrf=False,
                methods=['GET'])
    def signin(self, **kw):
        "TODO: Get parameters from header"        
        username = request.httprequest.headers.get('login')
        password = request.httprequest.headers.get('password')
        db = request.httprequest.headers.get('db')
        _logger.warning("username: " + username)
        _logger.warning("password: " + password)
        _logger.warning("db: " + db)
        rs = {}
        try:
            request.session.update(http.get_default_session(), db=db)
            auth = request.session.authenticate(db, username, password)
            user = request.env['res.users'].browse(auth)
            api_key = request.env.user.generate_api(username)
            datas = json.dumps({"Status": "auth successful",
                                "User": user.name,
                                "api-key": api_key})
           
            return request.make_response(data=datas)
        except:
            
            return "WrongUSerNamePasswor"
        
    
    # @http.route(['/odoo_connect'], type="http", auth="none", csrf=False,
    #             methods=['GET'])
    # def odoo_connect(self, **kw):
    #     """This is the controller which initializes the api transaction by
    #     generating the api-key for specific user and database"""
    #     _logger.warning("1123")
    #     return "Hello1"


    @http.route("/test", auth='none', type='http', csrf=False, methods=['GET'])
    def get_test(self, **kw):
        print("Test")
        response = {'message': "Test Test 123"}
        return request.make_response(json.dumps(response), headers={'Content-Type': 'application/json'})


    @http.route("/user/getInfo", auth='user', type='http', csrf=False, methods=['GET'])
    def getInfo(self, **kw):
        user = request.env.user
        current_user = {
            "uid": user.id,
            "name": user.name
        }
        print(current_user)
        
        return request.make_response(json.dumps(current_user), headers={'Content-Type': 'application/json'})
    
    @http.route("/sale/orders", auth='none', type='http', csrf=False, methods=['GET'])
    def getOrders(self, **kw):
        print("Test")
        response = {'message': "Test Test 123"}
        user = request.env.user.id
        print(user)
        # current_user = request.env['sale.order'].search([('user_id', '=', user)])
        current_user = request.env['sale.order'].search([])
        print(current_user)
        user = []
        for rec in current_user: 
            user.append(rec.name)
        
        # current_user = request.env.user.name
        # user = current_user
        return request.make_response(json.dumps(user), headers={'Content-Type': 'application/json'})
    
    @http.route("/authenticate", auth='none', type='http', csrf=False, methods=['GET'])
    def getAuthenticate(self, **kw):
        print("Test")
        response = {'message': "Test Test 123"}
        user = request.env.user.id
        print(user)
        # current_user = request.env['sale.order'].search([('user_id', '=', user)])
        current_user = request.env['sale.order'].search([])
        print(current_user)
        user = []
        for rec in current_user: 
            user.append(rec.name)
        
        # current_user = request.env.user.name
        # user = current_user
        return request.make_response(json.dumps(user), headers={'Content-Type': 'application/json'})
    
    @http.route("/validate_client_id", auth='none', type='http', csrf=False, methods=['GET'])
    def validate_client_id(self, **kw):

        client_id = request.httprequest.headers.get('client_id')
        print("1")
        search = request.env['oauth2.clien.model'].sudo().search([])
        data = []
        for rec in data: 
            data.append(rec.client_id)
        return request.make_response(json.dumps(data), headers={'Content-Type': 'application/json'})
