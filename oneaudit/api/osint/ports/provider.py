from oneaudit.api.provider import OneAuditBaseProvider


class OneAuditPortScanningAPIProvider(OneAuditBaseProvider):
    """
    Implementation of an API related to port scanning.
    """
    def __init__(self, api_name, request_args, api_keys):
        super().__init__(api_name, request_args, api_keys)

    def find_open_ports_by_ip(self, ip_address):
         yield True, {}
