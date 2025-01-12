from urllib.parse import urlparse

from oneaudit.api.osint.dns import DNSCapability, DomainInformation
from oneaudit.api.osint.dns.provider import OneAuditDNSAPIProvider


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
        self.request_args['url'] = self.api_endpoint.format(domain=domain)
        cached, results = self.fetch_results_using_cache(f"{domain}", default=[])
        yield cached, {"subdomains": [
            DomainInformation(urlparse(result[2]).netloc.split(":")[0], None)
            for result in results
            if result[2].startswith("http")
        ]}
