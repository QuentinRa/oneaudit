from oneaudit.api.osint.dns import DNSCapability
from oneaudit.api.osint.dns.provider import OneAuditDNSAPIProvider


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

    def dump_subdomains_from_domain(self, domain):
        # Check subdomains
        self.request_args['url'] = self.api_endpoint.format(domain=domain, type="subdomains")
        cached, data = self.fetch_results_using_cache(key=f"subdomains_{domain}", default={'data': []})

        for entry in data['data']:
            print(entry['id'])
            print(entry['type'])
            print(entry['attributes']['last_dns_records'])

        yield cached, {'subdomains': []}
