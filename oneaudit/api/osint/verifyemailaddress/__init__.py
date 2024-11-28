from random import randint
from oneaudit.api.osint import OSINTProvider, OSINTScrappedEmailDataFormat

# fixme: add back delete code
class VerifyEmailAddressAPI(OSINTProvider):
    def __init__(self, api_keys):
       super().__init__(
           api_name='verifyemailaddress',
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

    def is_email_valid(self, email):
        # todo: verify using pattern

        # Use the API
        self.request_args['data']['email'] = email
        cached, data = self.fetch_results_using_cache(email)
        return cached, OSINTScrappedEmailDataFormat(
            email,
            data['status'] == "valid"
        )
