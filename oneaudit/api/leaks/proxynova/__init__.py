from oneaudit.api.leaks import LeaksAPICapability
from oneaudit.api.leaks.provider import OneAuditLeaksAPIProvider
from oneaudit.api import FakeResponse
from requests import request
from time import sleep

# https://www.proxynova.com/tools/comb
class ProxyNovaAPI(OneAuditLeaksAPIProvider):
    def _init_capabilities(self, api_key, api_keys):
        return [LeaksAPICapability.INVESTIGATE_LEAKS_BY_EMAIL] if api_key is not None else []

    def handle_request(self):
        response = request(**self.request_args)
        if response.status_code == 400 or response.status_code == 502:
            if self.kill_switch < 3:
                self.logger.debug(f"{self.api_name} was rate-limited, waiting a few seconds.")
                self.handle_rate_limit(response)
                if response.status_code != 502:
                    self.kill_switch += 1
                return self.handle_request()
            else:
                self.logger.error(f"{self.api_name} could not process '{self.request_args["url"]}'.")
                return FakeResponse(204, {"lines": []})
        self.kill_switch = 0
        return response

    def handle_rate_limit(self, response):
        sleep(2)

    def get_request_rate(self):
        return 0.5

    def __init__(self, api_keys):
        super().__init__(
            api_name='proxynova',
            request_args={
                'method': 'GET'
            },
            api_keys=api_keys
        )
        self.api_endpoint = 'https://api.proxynova.com/comb?query={email}&start=0&limit=20'
        self.kill_switch = 0

    def investigate_leaks_by_email(self, email):
        # Update parameters
        self.request_args['url'] = self.api_endpoint.format(email=email)
        # Send the request
        cached, data = self.fetch_results_using_cache(email, default=None)
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
