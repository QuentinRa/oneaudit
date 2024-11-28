from oneaudit.api.provider import OneAuditBaseProvider


class OneAuditLeaksAPIProvider(OneAuditBaseProvider):
    """
    Implementation of an API related to leaks.
    """
    def __init__(self, api_name, request_args, api_keys):
        super().__init__(api_name, request_args, api_keys)