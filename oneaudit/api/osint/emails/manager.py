from oneaudit.api.manager import OneAuditBaseAPIManager

class OneAuditEmailsAPIManager(OneAuditBaseAPIManager):
    """
    APIs related to emails
    """

    def __init__(self, api_keys):
        from oneaudit.api.osint.emails import emailverifier
        super().__init__([
            # FREE
            emailverifier.EmailVerifiedOnlineAPI(api_keys)
            # FREEMIUM
            # PAID
        ])
