from oneaudit.api.osint.dns import DNSCapability, DomainInformation
from oneaudit.api.osint.dns.provider import OneAuditDNSAPIProvider


class CertSpotterAPI(OneAuditDNSAPIProvider):
    def get_request_rate(self):
        return 1

    def _init_capabilities(self, api_key, api_keys):
        return [DNSCapability.FETCH_WILDCARD_DOMAINS, DNSCapability.SUBDOMAINS_ENUMERATION] if api_key is not None else []

    def __init__(self, api_keys):
        super().__init__(
            api_name='certspotter',
            request_args={
                'method': 'GET'
            },
            api_keys=api_keys
        )
        self.api_endpoint = 'https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names'

    def dump_wildcard_domains_from_domain(self, domain):
        self.request_args['url'] = self.api_endpoint.format(domain=domain)
        cached, result = self.fetch_results_using_cache(f"{domain}", default=[])
        yield cached, {'wildcard': [dns_name[2:] for cert in result for dns_name in cert['dns_names'] if "*" in dns_name]}

    def dump_subdomains_from_domain(self, domain):
        self.request_args['url'] = self.api_endpoint.format(domain=domain)
        cached, result = self.fetch_results_using_cache(f"{domain}", default=[])
        yield cached, {'subdomains': [DomainInformation(dns_name, None) for cert in result for dns_name in cert['dns_names'] if "*" not in dns_name and dns_name != domain]}
