from oneaudit.api.socosint.linkedin.provider import OneAuditLinkedInAPIProvider
from random import randint


class RocketReachAPI(OneAuditLinkedInAPIProvider):
    def _init_capabilities(self, api_key, api_keys):
        return [] if api_key is not None else []

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

    def get_request_rate(self):
        return 5
