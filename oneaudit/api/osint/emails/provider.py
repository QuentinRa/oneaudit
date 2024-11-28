from oneaudit.api.osint.data import VerifiableEmail
from oneaudit.api.provider import OneAuditBaseProvider


class OneAuditEmailsAPIProvider(OneAuditBaseProvider):
    """
    Implementation of an API related to emails.
    """
    def __init__(self, api_name, request_args, api_keys):
        super().__init__(api_name, request_args, api_keys)

    def is_email_valid(self, email):
         yield True, VerifiableEmail(email, False)
