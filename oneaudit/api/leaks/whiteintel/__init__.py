from oneaudit.api.leaks import LeaksProvider, CensoredCredentialsLeakDataFormat
import time


# https://docs.whiteintel.io/whiteintel-api-doc
class WhiteIntelAPI(LeaksProvider):
    def __init__(self, api_keys):
        super().__init__(
            api_name='whiteintel',
            request_args={
                'method': 'POST',
                'json': {},
                'headers': {
                    'Authorization': f'Bearer {api_keys.get('whiteintel', None)}'
                }
            },
            api_keys=api_keys
        )
        self.api_endpoint = 'https://whiteintel.io/api/regular/app{endpoint}'

    def fetch_domain_results(self, domain):
        # Fetching Leaked URLs
        self.request_args['url'] = self.api_endpoint.format(endpoint='/attack_surface_handler.php')
        self.request_args['json'] = {
            'domain': domain,
            'page': 1, 'per_page': 25
        }
        cached, data = self.fetch_results_using_cache(f"attack_surface_{domain}")
        yield cached, {'leaked_urls': [leak['url'] for leak in data['leak_urls_customer']]}

        # Fetching Info Stealer And Comb Credentials
        for endpoint_url, details_url in [
            ('/stealer_exposure_handler_v2.php', '/breach_info_handler.php'),
            ('/combolist_exposure_handler_v2.php', '/breach_info_combolists_handler.php'),
            ('/stealer_exposure_employees_handler_v2.php', '/breach_info_employees_handler.php'),
        ]:
            self.request_args['url'] = self.api_endpoint.format(endpoint=endpoint_url)
            self.request_args['json'] = {
                'query': domain,
                'type': domain,
                'page': 1, 'per_page': 25
            }
            cached, data = self.fetch_results_using_cache(f"{get_key(endpoint_url)}_{domain}_page1")
            yield cached, {}

            for element in data['data']:
                self.request_args['url'] = self.api_endpoint.format(endpoint=details_url)
                self.request_args['json'] = {
                    'domain': domain,
                    'id': element['log_id']
                }

                cached, data = self.fetch_results_using_cache(f"{get_key(details_url)}_{domain}_{element['log_id']}")

                yield cached, {
                    'leaked_urls': [format_url(leak['URL']) for leak in data['credentials']],
                    'censored_data': [CensoredCredentialsLeakDataFormat(
                        leak['username'],
                        leak['password'],
                    ) for leak in data['credentials']]
                }

        yield cached, {}

    def handle_rate_limit(self, response):
        time.sleep(30)

    def get_rate(self):
        return 1

def format_url(URL):
    return URL if "://" in URL else f"https://{URL}"

def get_key(endpoint):
    return '_'.join(endpoint[1:].split('_')[:3])
