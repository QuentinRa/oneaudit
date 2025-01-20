from oneaudit.api.osint.dns import DNSCapability, DomainInformation
from oneaudit.api.osint.dns.provider import OneAuditDNSAPIProvider


# https://docs.virustotal.com/reference/overview
class VirusTotalAPI(OneAuditDNSAPIProvider):
    def _init_capabilities(self, api_key, api_keys):
        return [DNSCapability.SUBDOMAINS_ENUMERATION] if api_key is not None else []

    def get_request_rate(self):
        return 15

    def __init__(self, api_keys):
        super().__init__(
            api_name='virustotal',
            request_args={
                'method': 'GET',
                'headers': {
                    'accept': 'application/json'
                },
            },
            api_keys=api_keys
        )
        self.api_endpoint = 'https://www.virustotal.com/api/v3/domains/{domain}/{type}?limit=100'
        self.request_args['headers']['x-apikey'] = self.api_key
        self.allowed_status_codes = [200, 400]

    def dump_subdomains_from_domain(self, domain):
        # Check subdomains
        self.request_args['url'] = self.api_endpoint.format(domain=domain, type="subdomains")
        cached, data = self.fetch_results_using_cache(key=f"subdomains_{domain}", default={'data': []})
        if 'error' in data:
            data['data'] = []
        yield cached, {
            'subdomains':
                [DomainInformation(entry['id'], record['value'])
                 for entry in data['data']
                 for record in entry['attributes']['last_dns_records']
                 if record['type'] in ['A']]
        }
        # We should also check each domain for 'siblings'
