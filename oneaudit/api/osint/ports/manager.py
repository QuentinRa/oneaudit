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

    def scan_ports(self, target_ips):
        return {target_ip: [] for target_ip in target_ips}
