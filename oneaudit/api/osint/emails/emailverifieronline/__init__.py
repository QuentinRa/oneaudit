from oneaudit.api import APIRateLimitException
from oneaudit.api.osint.data import VerifiableEmail
from oneaudit.api.osint.emails import EmailAPICapability
from oneaudit.api.osint.emails.provider import OneAuditEmailsAPIProvider
from requests.exceptions import ReadTimeout
from random import randint


class EmailVerifiedOnlineAPI(OneAuditEmailsAPIProvider):
    def __init__(self, api_keys):
       super().__init__(
           api_name='emailverifieronline',
           request_args={
               'method': 'POST',
               'url': 'https://check.emailverifier.online/bulk-verify-email/functions/quick_mail_verify_no_session.php',
               'data': {
                   'index': 0,
                   'token': 12345,
                   'frommail': f'{randint(100000, 200000)}@qq.com',
                   'timeout': 10,
                   'scan_port': 25,
               },
               'timeout': 5
           },
           api_keys=api_keys
        )

    # CORE METHODS
    def is_email_valid(self, email):
        # Ask the API to check if an email is valid
        self.request_args['data']['email'] = email
        cached, data = self.fetch_results_using_cache(key=email)
        yield cached, VerifiableEmail(email, data['status'] == "valid")

    # CORE - END

    def _init_capabilities(self, api_key, api_keys):
        return [
            EmailAPICapability.EMAIL_VERIFICATION
        ] if api_key is not None else []

    def get_request_rate(self):
        return 5

    def handle_request(self, **kwargs):
        try:
            super().handle_request(**kwargs)
        except ReadTimeout:
            self.logger.error(f"API {self.api_name} is unresponsive. It was disabled.")
            self.handle_rate_limit(None)

    def handle_rate_limit(self, response):
        self.capabilities = []
        raise APIRateLimitException()