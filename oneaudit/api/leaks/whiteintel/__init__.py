from oneaudit.api.leaks import LeaksProvider

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
        self.request_args['json']['domain'] = domain
        self.request_args['json']['page'] = 1
        self.request_args['json']['per_page'] = 10
        cached, data = self.fetch_results_using_cache(f"attack_surface_{domain}")
        yield cached, {'leaked_urls': [leak['url'] for leak in data['leak_urls_customer']]}

    def handle_rate_limit(self, response):
        pass

    def get_rate(self):
        return 1