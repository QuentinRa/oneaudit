from oneaudit.api.leaks.provider import OneAuditLeaksAPIProvider, BreachDataFormat


# https://wiki.leakcheck.io/en/api
class LeakCheckAPI(OneAuditLeaksAPIProvider):
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
        self.api_key = api_keys.get('leakcheck_pro', None)
        self.is_public_endpoint_enabled = self.is_endpoint_enabled
        self.is_pro_endpoint_enabled = self.api_key is not None
        self.is_endpoint_enabled = self.is_public_endpoint_enabled or self.is_pro_endpoint_enabled
        self.show_notice()

    def fetch_email_results(self, email):
        if self.is_public_endpoint_enabled:
            # Update parameters
            self.request_args['headers']['X-API-Key'] = ''
            self.request_args['url'] = 'https://leakcheck.io/api/public'
            self.request_args['params'] = {'check': email}
            # Send the request
            cached, data = self.fetch_results_using_cache(f"public_{email}")
            sources = data['sources'] if 'sources' in data else []
            results = {
                'breaches': [BreachDataFormat(source["name"], source["date"]) for source in sources]
            }
            yield cached, results
            if not sources:
                return True, {}

        if self.is_pro_endpoint_enabled:
            self.request_args['headers']['X-API-Key'] = self.api_key
            self.request_args['url'] = f'https://leakcheck.io/api/v2/query/{email}'
            try:
                cached, data = self.fetch_results_using_cache(f"pro_{email}")
                if 'result' not in data:
                    raise Exception(f"Unexpected result for {self.api_name}: {data}")
                sources = [entry['source'] for entry in data['result'] if 'source' in entry]
                results = {
                    'passwords': [entry['password'] for entry in data['result'] if 'password' in entry],
                    'breaches': [BreachDataFormat(source["name"], source["breach_date"])
                                 for source in sources if source['name'] != "Unknown"],
                }
                yield cached, results
            except PaidAPIDisabledException:
                yield False, {}

    def handle_rate_limit(self, response):
        if 'Limit reached' in response.text:
            self.logger.error(f"Provider {self.api_name} was disabled due to rate-limit.")
            self.is_pro_endpoint_enabled = False
            self.is_endpoint_enabled = self.is_public_endpoint_enabled
            raise PaidAPIDisabledException(f"{response.text}")

    def handle_request(self, **kwargs):
        response = super().handle_request(**kwargs)
        if response.status_code != 403:
            return response
        self.handle_rate_limit(response)

    def get_request_rate(self):
        return 1