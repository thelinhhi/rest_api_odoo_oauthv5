

from odoo import fields, models, api
import hashlib
import uuid
import logging

from ..oauth2.validator import OdooValidator

_logger = logging.getLogger(__name__)

try:
    from ..oauthlib import oauth2
except ImportError as e:
    _logger.debug('Cannot `import oauthlib`.')
    print(e)

class Oauth2ClientModel(models.Model):
    """This class is used to inherit users and add api key generation"""
    _name = 'oauth2.client.model'
    _description = ''

    user_id = fields.Many2one(comodel_name='res.users',
    		       string='User Id')

    client_id = fields.Char(
        string="Client Identifier", 
        required=True, 
        # readonly=True,
        default=lambda self: str(uuid.uuid4()),
        size=100,           
        help="Required. The identifier the client will use during the OAuth workflow. Structure is up to you and may be a simple UUID.")
    
    application_name = fields.Text(string='Application Name')
    
    _sql_constraints = [
                     ('client_id_unique', 
                      'unique(client_id)',
                      'Choose another value - it has to be unique!')
    ]

    client_secret = fields.Char(
        help='Optional secret used to authenticate the client.')

    skip_authorization = fields.Boolean(
        help='Check this box if the user shouldn\'t be prompted to authorize '
        'or not the requested scopes.')
    
    application_type = fields.Selection(
        selection=[
            ('web application', 'Web Application'),
            ('mobile application', 'Mobile Application'),
            ('legacy application', 'Legacy Application'),
            ('backend application', 'Backend Application (not implemented)'),
        ], required=True, default='web application',
        help='Application type to be used with this client.')

    grant_type = fields.Selection(
        selection=[
            ('authorization_code', 'Authorization code')
            ], 
            string='OAuth Grant Type')
    
    response_type = fields.Selection(
        selection=[
            ('code', 'Authorization code'),
            ('token', 'Token'),
            ('none', 'None'),
            ], 
        string='My Selection response type')


    token_type = fields.Selection(
        selection=[('random', 'Randomly generated')],
        required=True, default='random',
        help='Type of token to return. The base module only provides randomly '
        'generated tokens.')
    
    scopes = fields.Text()

    redirect_uris = fields.Text()


    def get_oauth2_server(self, validator=None, **kwargs):
        """ Returns an OAuth2 server instance, depending on the client application type

        Generates an OdooValidator instance if no custom validator is defined
        All other arguments are directly passed to the server constructor (for
        example, a token generator function)
        """
        self.ensure_one()
        
        if validator is None:
            validator = OdooValidator()

        # return oauth2.WebApplicationServer(validator, **kwargs)
    
        if self.application_type == 'web application':
            return oauth2.WebApplicationServer(validator, **kwargs)
        elif self.application_type == 'mobile application':
            return oauth2.MobileApplicationServer(validator, **kwargs)
        elif self.application_type == 'legacy application':
            return oauth2.LegacyApplicationServer(validator, **kwargs)
        elif self.application_type == 'backend application':
            return oauth2.BackendApplicationServer(validator, **kwargs)
        
    
