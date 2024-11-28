from oneaudit.api.osint.data import VerifiableEmail
from oneaudit.api.osint.emails import EmailAPICapability
from oneaudit.api.osint.emails.provider import OneAuditEmailsAPIProvider
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
               }
           },
           api_keys=api_keys
        )

    def _init_capabilities(self, api_key, api_keys):
        return [
            EmailAPICapability.EMAIL_VERIFICATION
        ] if api_key is not None else []

    def get_request_rate(self):
        return 5

    def is_email_valid(self, email):
        self.request_args['data']['email'] = email
        cached, data = self.fetch_results_using_cache(key=email)
        yield cached, VerifiableEmail(email, data['status'] == "valid")
