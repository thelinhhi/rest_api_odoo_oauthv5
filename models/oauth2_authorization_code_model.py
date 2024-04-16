# -*- coding:utf-8 -*-
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

import uuid
from odoo import fields, models

class Oauth2AuthorizationCodeModel(models.Model):
    _name = 'oauth2.authorization.code.model'
    _description = ''

    # client_id = fields.Text()
    client_id = fields.Many2one(comodel_name='oauth2.client.model',
    		       string='Client Id')
    user_id = fields.Text()
    
    scopes = fields.Text()

    redirect_uris = fields.Text()

    code = fields.Char(string="Code", size=100, 
                          help="")
    
    _sql_constraints = [
                     ('unique_code', 
                      'unique(code)',
                      'Choose another value - it has to be unique!')
    ]

    expires_at = fields.Datetime()

    challenge = fields.Char(string="challenge", size=128, 
                          help="")
    
    challenge_method = fields.Char(string="challenge method", size=6, 
                          help="")
    # def generate_api(self, username):
    #     """This function is used to generate api-key for each user"""
    #     users = self.env['res.users'].sudo().search([('login', '=', username)])
    #     if not users.api_key:
    #         users.api_key = str(uuid.uuid4())
    #         key = users.api_key
    #     else:
    #         key = users.api_key
    #     return key
