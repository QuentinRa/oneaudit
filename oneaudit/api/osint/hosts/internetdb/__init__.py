from oneaudit.api.osint.hosts import HostScanningAPICapability
from oneaudit.api.osint.hosts.provider import OneAuditPortScanningAPIProvider


# https://internetdb.shodan.io/
class InternetDBAPI(OneAuditPortScanningAPIProvider):
    def _init_capabilities(self, api_key, api_keys):
        return [HostScanningAPICapability.HOST_SCANNING] if api_key is not None else []

    def get_request_rate(self):
        return 1.75

    def __init__(self, api_keys):
        super().__init__(
            api_name='internetdb',
            request_args={
                'method': 'GET',
            },
            api_keys=api_keys
        )
        self.api_endpoint = 'https://internetdb.shodan.io/{ip_address}'
        self.allowed_status_codes =[200, 404]

    def investigate_host_by_ip(self, ip_address):
        self.request_args['url'] = self.api_endpoint.format(ip_address=ip_address)
        cached, result = self.fetch_results_using_cache(f"ip_{ip_address}", default={})
        yield cached, {
            'ports': result['ports'] if 'ports' in result else [],
            'stack': result['cpes'] if 'cpes' in result else [],
            'vulns': result['vulns'] if 'vulns' in result else [],
        }
