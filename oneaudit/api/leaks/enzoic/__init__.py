from oneaudit.api.leaks import LeaksAPICapability
from oneaudit.api.leaks.provider import OneAuditLeaksAPIProvider
from time import sleep
from base64 import b64encode


# https://docs.enzoic.com/enzoic-api-developer-documentation
class EnzoicAPI(OneAuditLeaksAPIProvider):
    def _init_capabilities(self, api_key, api_keys):
        return [LeaksAPICapability.INVESTIGATE_LEAKS_BY_EMAIL, LeaksAPICapability.INVESTIGATE_BULK] if api_key is not None else []

    def handle_rate_limit(self, response):
        sleep(30)

    def get_request_rate(self):
        return 1

    def __init__(self, api_keys):
        super().__init__(
            api_name='enzoic',
            request_args={
                'method': 'GET',
                'url': 'https://api.enzoic.com/v1/exposures-for-usernames',
                'params': {
                    'includeExposureDetails': 1
                }
            },
            api_keys=api_keys
        )
        self.request_args['headers']['authorization'] = f'basic {b64encode(self.api_key).decode()}' if self.api_key else ''

    def investigate_leaks_by_email(self, email):
        self.only_use_cache = True
        _, data = self.fetch_results_using_cache(f"exposures_{email}", default={})
        print(data)
        yield True, {}
