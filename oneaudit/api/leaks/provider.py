from oneaudit.api.leaks import PasswordHashDataFormat
from oneaudit.api.provider import OneAuditBaseProvider
from oneaudit.api.utils.caching import get_cached_result, set_cached_result
from oneaudit.utils.io import compute_checksum


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

    def _cache_indexed_data_if_required(self, key_format, indexed_data):
        key_formatter = f'{self.api_name}_{key_format}'
        for key, extracted_data in indexed_data.items():
            # Compute checksum
            cached_data = get_cached_result(self.api_name, key_formatter.format(key=key), True)
            cached_data_checksum = cached_data['checksum_sha256'] if cached_data and 'checksum_sha256' in cached_data else None
            extracted_data_checksum = compute_checksum(extracted_data)
            # Update database if data changed
            if extracted_data_checksum != cached_data_checksum:
                set_cached_result(self.api_name, key_formatter.format(key=key), {'checksum_sha256': extracted_data_checksum, **self._generate_cached_from_extracted(extracted_data)})

    def _generate_cached_from_extracted(self, extracted_data):
        return { "result": extracted_data }
