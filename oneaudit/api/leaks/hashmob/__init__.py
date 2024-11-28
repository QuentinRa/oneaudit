from oneaudit.api.leaks import LeaksAPICapability
from oneaudit.api.leaks.provider import OneAuditLeaksAPIProvider, PasswordHashDataFormat


# https://hashmob.net/api/v2/documentation
class HashMobAPI(OneAuditLeaksAPIProvider):
    def _init_capabilities(self, api_key, api_keys):
        return [LeaksAPICapability.INVESTIGATE_CRACKED_HASHES] if api_key is not None else []

    # Minimum rate is "0.2" for 5 requests/second
    def get_request_rate(self):
        return 1

    def __init__(self, api_keys):
        super().__init__(
            api_name='hashmob',
            request_args={
                'method': 'POST',
                'url': 'https://hashmob.net/api/v2/search',
                'json': {},
                'headers': {}
            },
            api_keys=api_keys
        )
        self.request_args['headers']['api-key'] = self.api_key

    def lookup_plaintext_from_hash(self, hash_to_crack):
        self.request_args['json']['hashes'] = [hash_to_crack]
        cached, data = self.fetch_results_using_cache(hash_to_crack)
        if 'data' not in data and 'found' not in data['data']:
            raise Exception(f"Unexpected answer for {self.api_name}: {data}")

        found = data['data']['found']

        return cached, PasswordHashDataFormat(
            value=hash_to_crack,
            plaintext=None if len(found) == 0 else found[0]['plain'],
            format=None,
            format_confidence=-1
        )