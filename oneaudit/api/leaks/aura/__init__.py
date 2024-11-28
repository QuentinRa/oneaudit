from oneaudit.api.leaks.provider import OneAuditLeaksAPIProvider
import time
import requests

# https://scan.aura.com/
class AuraAPI(OneAuditLeaksAPIProvider):
    def __init__(self, api_keys):
        super().__init__(
            api_name='aura',
            request_args={
                'url': 'https://scan.aura.com/results?_data=routes%2Fresults',
            },
            api_keys=api_keys
        )
        self.rate_limit_status_codes = [429, 500]

    def fetch_email_results(self, email):
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

    def handle_request(self):
        s = requests.Session()
        s.post(**self.request_args)
        if 'data' not in self.request_args:
            self.logger.error(f"{self.api_name}: unexpected answer to POST request. Trying again after a delay.")
            self.handle_rate_limit(None)
            return self.handle_request()
        del self.request_args['data']
        return s.get(**self.request_args)

    def handle_rate_limit(self, response):
        time.sleep(15)

    def get_request_rate(self):
        return 5