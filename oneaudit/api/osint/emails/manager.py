from oneaudit.api.manager import OneAuditBaseAPIManager
from oneaudit.api.osint.emails.data import EmailAPICapability


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

    def verify_emails(self, emails):
        results = {}
        for email in emails:
            # Handling duplicates
            if email in results:
                continue

            # Query all email APIs that can verify emails
            valid_result = None
            for api_result in self._call_all_providers(
                    heading="Verifying emails",
                    capability=EmailAPICapability.EMAIL_VERIFICATION,
                    method_name='is_email_valid',
                    args=(email,)):
                if api_result.verified:
                    valid_result = api_result
                    break

            if valid_result:
                self.logger.info(f"Found valid email: {email}")
                results[email] = valid_result

        return list(results.values())
