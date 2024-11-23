from oneaudit.api.leaks import LeaksProvider, CensoredCredentialsLeakDataFormat


# https://docs.whiteintel.io/whiteintel-api-doc
class WhiteIntelAPI(LeaksProvider):
    def __init__(self, api_keys):
        super().__init__(
            unique_identifier='whiteintel_regular_',
            request_args={
                'method': 'POST',
                'json': {},
                'headers': {
                    'Authorization': f'Bearer {api_keys.get('whiteintel', None)}'
                }
            }
        )
        self.is_endpoint_enabled = self.request_args['headers']['Authorization'] is not None
        self.api_endpoint = 'https://whiteintel.io/api/regular/app{endpoint}'

    def fetch_domain_results(self, domain):
        if not self.is_endpoint_enabled:
            yield super().fetch_domain_results(domain)

        # Fetching Leaked URLs
        self.request_args['url'] = self.api_endpoint.format(endpoint='/attack_surface_handler.php')
        self.request_args['json'] = {
            'domain': domain,
            'page': 1, 'per_page': 25
        }
        cached, data = self.fetch_results_using_cache(f"attack_surface_{domain}")
        yield cached, {'leaked_urls': [leak['url'] for leak in data['leak_urls_customer']]}

        # Fetching Info Stealers
        self.request_args['url'] = self.api_endpoint.format(endpoint='/stealer_exposure_handler_v2.php')
        self.request_args['json'] = {
            'query': domain,
            'type': domain,
            'page': 1, 'per_page': 25
        }
        cached, data = self.fetch_results_using_cache(f"stealer_exposure_{domain}")
        yield cached, {}

        for stealer in data['data']:
            self.request_args['url'] = self.api_endpoint.format(endpoint='/breach_info_handler.php')
            self.request_args['json'] = {
                'domain': domain,
                'id': stealer['log_id']
            }

            cached, data = self.fetch_results_using_cache(f"breach_info_{domain}")

            yield cached, {
                'leaked_urls': [leak['URL'] for leak in data['credentials']],
                'censored_data': [CensoredCredentialsLeakDataFormat(
                    leak['username'],
                    leak['password'],
                ) for leak in data['credentials']]
            }

        yield cached, {}

    def handle_rate_limit(self, response):
        pass

    def get_rate(self):
        return 1