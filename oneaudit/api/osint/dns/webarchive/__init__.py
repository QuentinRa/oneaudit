from urllib.parse import urlparse

from oneaudit.api.leaks import deserialize_result
from oneaudit.api.osint.dns import DNSCapability, DomainInformation
from oneaudit.api.osint.dns.provider import OneAuditDNSAPIProvider
from oneaudit.api.utils.caching import get_cached_result


class WebArchiveAPI(OneAuditDNSAPIProvider):
    def get_request_rate(self):
        return 1

    def _init_capabilities(self, api_key, api_keys):
        return [DNSCapability.SUBDOMAINS_ENUMERATION] if api_key is not None else []

    def __init__(self, api_keys):
        super().__init__(
            api_name='webarchive',
            request_args={
                'method': 'GET'
            },
            api_keys=api_keys
        )
        self.api_endpoint = 'https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json'

    def dump_subdomains_from_domain(self, domain):
        cache_key = f'{self.api_name}_parsed_domains_{domain}'
        cached, result = True, get_cached_result(self.api_name, cache_key)
        if not result:
            self.request_args['url'] = self.api_endpoint.format(domain=domain)
            cached, results = self.fetch_results_using_cache(f"{domain}", default=[])
            result = {"subdomains": list(set([
                DomainInformation(urlparse(result[2]).netloc.split(":")[0], None)
                for result in results
                if result[2].startswith("http")
            ]))}
            self._cache_indexed_data_if_required("parsed_domains_{key}", {
                domain: result
            })
        else:
            result = {
                'subdomains': [DomainInformation(d['domain_name'], None) for d in result['result']['subdomains']]
            }

        yield cached, result
