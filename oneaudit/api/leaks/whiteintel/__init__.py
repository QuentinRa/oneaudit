from oneaudit.api.leaks import CensoredCredentials, CensoredInfoStealers, LeaksAPICapability
from oneaudit.api.leaks.provider import OneAuditLeaksAPIProvider
import time


# https://docs.whiteintel.io/whiteintel-api-doc
class WhiteIntelAPI(OneAuditLeaksAPIProvider):
    def _init_capabilities(self, api_key, api_keys):
        return [LeaksAPICapability.INVESTIGATE_LEAKS_BY_DOMAIN] if api_key is not None else []

    def handle_rate_limit(self, response):
        time.sleep(30)

    def get_request_rate(self):
        return 1

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

    def investigate_leaks_by_domain(self, domain):
        # Fetching Leaked URLs
        self.request_args['url'] = self.api_endpoint.format(endpoint='/attack_surface_handler.php')
        self.request_args['json'] = {
            'domain': domain,
            'page': 1, 'per_page': 25
        }
        cached, data = self.fetch_results_using_cache(f"attack_surface_{domain}", default={'leak_urls_customer': []})
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
            cached, data = self.fetch_results_using_cache(f"{get_key(endpoint_url)}_{domain}_page1", default={'data': []})
            yield cached, {}

            for element in data['data']:
                self.request_args['url'] = self.api_endpoint.format(endpoint=details_url)
                self.request_args['json'] = {
                    'domain': domain,
                    'id': element['log_id']
                }

                cached, data = self.fetch_results_using_cache(f"{get_key(details_url)}_{domain}_{element['log_id']}", default={'credentials': []})

                yield cached, {
                    'leaked_urls': [format_url(leak['URL']) for leak in data['credentials']],
                    'censored_creds': [CensoredCredentials(
                        leak['username'],
                        leak['password'],
                    ) for leak in data['credentials']],
                    'censored_stealers': [CensoredInfoStealers(
                        element['device_id'],
                        element['breach_date'],
                    ) ] if 'device_id' in element else []
                }

        yield cached, {}


def format_url(URL):
    return URL if "://" in URL else f"https://{URL}"

def get_key(endpoint):
    return '_'.join(endpoint[1:].split('_')[:3])
