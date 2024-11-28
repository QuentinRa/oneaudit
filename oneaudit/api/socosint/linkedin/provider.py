from oneaudit.api.provider import OneAuditBaseProvider


class OneAuditLinkedInAPIProvider(OneAuditBaseProvider):
    """
    Implementation of an API related to emails.
    """
    def __init__(self, api_name, request_args, api_keys):
        super().__init__(api_name, request_args, api_keys)
