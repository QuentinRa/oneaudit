from ipaddress import ip_address, ip_network
from oneaudit.api.manager import OneAuditBaseAPIManager
from oneaudit.api.osint.ports import PortScanningAPICapability
from oneaudit.api.osint.ports import internetdb

class OneAuditPortScanningAPIManager(OneAuditBaseAPIManager):
    """
    APIs related to emails
    """
    def __init__(self, api_keys):
        super().__init__([
            # FREE
            internetdb.InternetDBAPI(api_keys),
            # FREEMIUM
            # PAID
        ])

    def scan_ports(self, base_target_ips, resolved_domains):
        target_ips = [ip_network(ip if '/' in ip else f'{ip}/32')  for ip in base_target_ips]
        resolved_domains = {} if not resolved_domains else resolved_domains

        final_result = {}
        for ip_range in target_ips:
            for target_ip in ip_range:
                target_ip = str(target_ip)
                if target_ip in final_result:
                    continue
                _, result = self._call_all_providers_dict(
                    heading="Scanning ports",
                    capability=PortScanningAPICapability.PORT_SCANNING,
                    method_name='find_open_ports_by_ip',
                    stop_when_modified=False,
                    result={'ports': [], 'details': [], 'domains': resolved_domains[target_ip] if target_ip in resolved_domains else []},
                    args=(target_ip,)
                )
                final_result[target_ip] = {
                    'ports': sorted([e for e in set(result['ports']) if e]),
                    'details': result['details'],
                    'domains': sorted([e for e in set(result['domains']) if e]),
                }
        return final_result