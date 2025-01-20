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
            for _target_ip in ip_range:
                target_ip = str(_target_ip)
                # Technically, we don't 'mind' scanning private IP addresses, but the results are meaningless
                # As providers will likely respond with 404 or junk data
                if target_ip in final_result or _target_ip.is_private or _target_ip.is_link_local:
                    continue
                _, result = self._call_all_providers_dict(
                    heading="Scanning ports",
                    capability=PortScanningAPICapability.PORT_SCANNING,
                    method_name='find_open_ports_by_ip',
                    stop_when_modified=False,
                    result={'ports': [], 'stack': [], 'vulns': [], 'domains': resolved_domains[target_ip] if target_ip in resolved_domains else []},
                    args=(target_ip,)
                )
                final_result[target_ip] = {
                    'ports': sorted([e for e in set(result['ports']) if e]),
                    'stack': sorted([e for e in set(result['stack']) if e]),
                    'vulns': list(reversed(sorted([e for e in set(result['vulns']) if e]))),
                    'domains': sorted([e for e in set(result['domains']) if e]),
                }
        return final_result