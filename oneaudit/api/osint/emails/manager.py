from oneaudit.api.manager import OneAuditBaseAPIManager
from oneaudit.api.osint.emails import EmailAPICapability


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
        """
        Indicates for each email if the email is verified or not.
        """
        results = {}
        for email in emails:
            # Handling duplicates
            if email in results:
                continue

            # Query all email APIs that can verify emails
            email_data = None
            for api_result in self._call_all_providers(
                    heading="Verifying emails",
                    capability=EmailAPICapability.EMAIL_VERIFICATION,
                    method_name='is_email_valid',
                    args=(email,)):
                email_data = api_result
                if email_data.verified:
                    break

            if email_data:
                if email_data.verified:
                    self.logger.info(f"Found valid email: {email}")
                results[email] = email_data

        return list(results.values())
