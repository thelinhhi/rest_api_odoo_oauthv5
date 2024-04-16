
from odoo import fields, models, api
import hashlib
import uuid

class Oauth2ScopeTokenModel(models.Model):
    _name = 'oauth2.scope.model'
    _description = ''
    # client = fields.Many2one(comodel_name='oauth2.clien.model',
    # 		       string='Parent')

    # access_token = fields.Char(string="Access Token", size=100, 
    #                       help="")
    
    # _sql_constraints = [
    #                  ('unique_access_token', 
    #                   'unique(access_token)',
    #                   'Choose another value - it has to be unique!')
    # ]

    # expires_at = fields.Datetime()