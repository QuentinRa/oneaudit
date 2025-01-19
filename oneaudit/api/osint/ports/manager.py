from ipaddress import ip_address, ip_network

from oneaudit.api.manager import OneAuditBaseAPIManager
from oneaudit.api.osint.ports import PortScanningAPICapability


class OneAuditPortScanningAPIManager(OneAuditBaseAPIManager):
    """
    APIs related to emails
    """
    def __init__(self, api_keys):
        super().__init__([
            # FREE
            # FREEMIUM
            # PAID
        ])

    def scan_ports(self, base_target_ips):

        target_ips = [ip_network(ip if '/' in ip else f'{ip}/32')  for ip in base_target_ips]

        return {str(target_ip): self._call_all_providers_dict(
            heading="Verifying emails",
            capability=PortScanningAPICapability.PORT_SCANNING,
            method_name='find_open_ports_by_ip',
            stop_when_modified=False,
            result={'ports': []},
            args=(str(target_ip),))[1]['ports'] for ip_range in target_ips for target_ip in ip_range}
