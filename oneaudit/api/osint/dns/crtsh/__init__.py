from oneaudit.api.osint.dns import DNSCapability
from oneaudit.api.osint.dns.provider import OneAuditDNSAPIProvider


# https://crt.sh
class CrtShAPI(OneAuditDNSAPIProvider):
    def _init_capabilities(self, api_key, api_keys):
        return [DNSCapability.FETCH_WILDCARD_DOMAINS] if api_key is not None else []

    def __init__(self, api_keys):
        super().__init__(
            api_name='crtsh',
            request_args={
                'method': 'GET'
            },
            api_keys=api_keys
        )
        self.api_endpoint = 'https://crt.sh/?q={domain}&output=json'

    def dump_wildcard_domains_from_domain(self, domain):
        self.request_args['url'] = self.api_endpoint.format(domain=domain)
        cached, result = self.fetch_results_using_cache(f"cert_{domain}", default=[])
        yield cached, {'wildcard': [cert['common_name'][2:] for cert in result if "*" in cert['common_name']]}
