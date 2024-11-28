from oneaudit.api.manager import OneAuditBaseAPIManager


class OneAuditLinkedInAPIManager(OneAuditBaseAPIManager):
    """
    APIs related to emails
    """
    def __init__(self, api_keys, parsing_only=False):
        from oneaudit.api.socosint.linkedin import rocketreach
        super().__init__([
            # FREE
            # FREEMIUM
            # PAID
            rocketreach.RocketReachAPI(api_keys, parsing_only)
        ])


