
from odoo import fields, models, api
import hashlib
import uuid

class Oauth2BearerTokenModel(models.Model):
    _name = 'oauth2.bearer.token.model'
    _description = ''
    # client = fields.Many2one(comodel_name='oauth2.clien.model',
    # 		       string='Parent')

    access_token = fields.Char(string="Access Token", size=100, 
                          help="")
    
    _sql_constraints = [
                     ('unique_access_token', 
                      'unique(access_token)',
                      'Choose another value - it has to be unique!')
    ]

    device_id = fields.Char(string='Device Id')
    
    expires_in = fields.Integer()

    token_type = fields.Char(string="Token type", size=100, 
                          help="")
    
    refresh_token = fields.Char(string="Refresh token", size=100, 
                          help="")

    # scope = fields.