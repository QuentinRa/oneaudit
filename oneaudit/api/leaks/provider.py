from oneaudit.api.leaks import PasswordHashDataFormat
from oneaudit.api.provider import OneAuditBaseProvider


class OneAuditLeaksAPIProvider(OneAuditBaseProvider):
    """
    Implementation of an API related to leaks.
    """
    def __init__(self, api_name, request_args, api_keys):
        super().__init__(api_name, request_args, api_keys)

    def investigate_bulk(self, emails):
        yield True, {}

    def investigate_leaks_by_email(self, email, for_stats=False):
        yield True, {}

    def investigate_leaks_by_domain(self, domain):
        yield True, {}

    def investigate_breach_from_name(self, breach):
        yield True, []

    def lookup_plaintext_from_hash(self, hash_to_crack):
        yield True, PasswordHashDataFormat(value=hash_to_crack, plaintext=None, format=None, format_confidence=-1)


class OneAuditLeaksAPIBulkProvider(OneAuditLeaksAPIProvider):
    """
    Utilities for APIs that handle bulk queries
    """
    pass
