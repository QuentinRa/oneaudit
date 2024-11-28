from oneaudit.api.leaks import LeaksAPICapability, InfoStealer
from oneaudit.api.leaks.provider import OneAuditLeaksAPIProvider
from time import sleep


# https://cavalier.hudsonrock.com/docs
class HudsonRocksAPI(OneAuditLeaksAPIProvider):
    def _init_capabilities(self, api_key, api_keys):
        return [LeaksAPICapability.INVESTIGATE_LEAKS_BY_EMAIL] if api_key is not None else []

    def handle_rate_limit(self, response):
        sleep(60)

    def get_request_rate(self):
        return 0.5

    def __init__(self, api_keys):
        super().__init__(
            api_name='hudsonrocks',
            request_args={
                'method': 'GET',
                'url': 'https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email',
            },
            api_keys=api_keys
        )

    def investigate_leaks_by_email(self, email):
        # Update parameters
        self.request_args['params'] = {'email': email}
        # Send the request
        cached, data = self.fetch_results_using_cache(email, default={'stealers': []})
        result = {
            'info_stealers': [],
            'censored_logins': [],
            'censored_passwords': [],
        }
        for stealer in data['stealers']:
            result['info_stealers'].append(InfoStealer(
                stealer['computer_name'],
                stealer['operating_system'],
                stealer['date_compromised'],
            ))
            result['censored_logins'].extend(stealer['top_logins'])
            result['censored_passwords'].extend(stealer['top_passwords'])

        yield cached, result
