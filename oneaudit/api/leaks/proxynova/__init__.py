from oneaudit.api.leaks import LeaksProvider
from oneaudit.api import FakeResponse
import time
import requests

# https://www.proxynova.com/tools/comb
class ProxyNovaAPI(LeaksProvider):
    def __init__(self, api_keys):
        super().__init__(
            api_name='proxynova',
            request_args={
                'method': 'GET'
            },
            api_keys=api_keys
        )
        self.api_endpoint = 'https://api.proxynova.com/comb?query={email}&start=0&limit=100'
        self.kill_switch = 0

    def fetch_email_results(self, email):
        # Update parameters
        self.request_args['url'] = self.api_endpoint.format(email=email)
        # Send the request
        cached, data = self.fetch_results_using_cache(email)
        result = {
            'passwords': []
        }
        # API is overloaded
        if data is None:
            return result

        for line in data['lines']:
            if ':' not in line:
                continue
            username, *password = line.split(':')
            password = ''.join(password)
            if username == email:
                result['passwords'].append(password)

        yield cached, result

    def handle_request(self):
        response = requests.request(**self.request_args)
        if response.status_code == 400:
            if self.kill_switch < 3:
                self.logger.debug(f"{self.api_name} was rate-limited, waiting a few seconds.")
                self.handle_rate_limit(response)
                self.kill_switch += 1
                return self.handle_request()
            else:
                self.logger.error(f"{self.api_name} could not process '{self.request_args["url"]}'.")
                return FakeResponse(204, {"lines": []})
        self.kill_switch = 0
        return response

    def handle_rate_limit(self, response):
        time.sleep(2)

    def get_rate(self):
        return 0.5
