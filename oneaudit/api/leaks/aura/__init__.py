from oneaudit.api.leaks import LeaksAPICapability
from oneaudit.api.leaks.provider import OneAuditLeaksAPIProvider
from requests import Session
from time import sleep


# https://scan.aura.com/
class AuraAPI(OneAuditLeaksAPIProvider):
    def _init_capabilities(self, api_key, api_keys):
        return [LeaksAPICapability.INVESTIGATE_LEAKS_BY_EMAIL] if api_key is not None else []

    def get_request_rate(self):
        return 5

    def handle_request(self):
        s = Session()
        s.post(**self.request_args)
        if 'data' not in self.request_args:
            self.logger.error(f"{self.api_name}: unexpected answer to POST request. Trying again after a delay.")
            self.handle_rate_limit(None)
            return self.handle_request()
        del self.request_args['data']
        return s.get(**self.request_args)

    def handle_rate_limit(self, response):
        sleep(15)

    def __init__(self, api_keys):
        super().__init__(
            api_name='aura',
            request_args={
                'url': 'https://scan.aura.com/results?_data=routes%2Fresults',
            },
            api_keys=api_keys
        )
        self.rate_limit_status_codes = [429, 500]

    def investigate_leaks_by_email(self, email):
        # Update parameters
        self.request_args['data'] = {'email': email}
        # Send the request
        cached, data = self.fetch_results_using_cache(email)
        if 'results' not in data:
            self.logger.error(f"Unexpected response for {self.api_name}: {data}.")
            return cached, {}

        results = {
            'logins': [result['username'] for result in data['results'] if 'username' in result],
            'censored_passwords': [result['password'] for result in data['results'] if 'password' in result]
        }

        yield cached, results