from oneaudit.api import APIRateLimitException
from oneaudit.api.leaks import BreachData, LeaksAPICapability
from oneaudit.api.leaks.provider import OneAuditLeaksAPIProvider


# https://wiki.leakcheck.io/en/api
class LeakCheckAPI(OneAuditLeaksAPIProvider):
    def _init_capabilities(self, api_key, api_keys):
        capabilities = set()
        if api_key is not None:
            capabilities.add(LeaksAPICapability.INVESTIGATE_LEAKS_BY_EMAIL)
            capabilities.add(LeaksAPICapability.FREE_ENDPOINT)
        self.api_key = api_keys.get('leakcheck_pro')
        if self.api_key is not None:
            capabilities.add(LeaksAPICapability.INVESTIGATE_LEAKS_BY_EMAIL)
            capabilities.add(LeaksAPICapability.PAID_ENDPOINT)
        return list(capabilities)

    def handle_rate_limit(self, response):
        if 'Limit reached' in response.text:
            self.logger.error(f"Provider {self.api_name} was disabled due to rate-limit.")
            self.capabilities.remove(LeaksAPICapability.PAID_ENDPOINT)
            # If the PAID endpoint was the only one, we disable INVESTIGATE_LEAKS_BY_EMAIL
            if len(self.capabilities) == 1:
                self.capabilities = []
            raise APIRateLimitException(f"{response.text}")

    def handle_request(self, **kwargs):
        response = super().handle_request(**kwargs)
        if response.status_code != 403:
            return response
        self.handle_rate_limit(response)

    def get_request_rate(self):
        return 1

    def __init__(self, api_keys):
        super().__init__(
            api_name='leakcheck',
            request_args={
                'method': 'GET',
                'headers': {
                    'X-API-Key': ''
                }
            },
            api_keys=api_keys
        )

    def investigate_leaks_by_email(self, email):
        if LeaksAPICapability.FREE_ENDPOINT in self.capabilities or self.only_use_cache:
            # Update parameters
            self.request_args['headers']['X-API-Key'] = ''
            self.request_args['url'] = 'https://leakcheck.io/api/public'
            self.request_args['params'] = {'check': email}
            # Send the request
            cached, data = self.fetch_results_using_cache(f"public_{email}", default={})
            sources = data['sources'] if 'sources' in data else []
            results = {
                'breaches': [BreachData(source["name"], source["date"]) for source in sources]
            }
            yield cached, results

        if LeaksAPICapability.PAID_ENDPOINT in self.capabilities or self.only_use_cache:
            self.request_args['headers']['X-API-Key'] = self.api_key
            self.request_args['url'] = f'https://leakcheck.io/api/v2/query/{email}'
            try:
                cached, data = self.fetch_results_using_cache(f"pro_{email}", default={'result': []})
                if 'result' not in data:
                    raise Exception(f"Unexpected result for {self.api_name}: {data}")
                sources = [entry['source'] for entry in data['result'] if 'source' in entry]
                results = {
                    'passwords': [entry['password'] for entry in data['result'] if 'password' in entry],
                    'breaches': [BreachData(source["name"], source["breach_date"])
                                 for source in sources if source['name'] != "Unknown"],
                }
                yield cached, results
            except APIRateLimitException:
                yield True, {}
