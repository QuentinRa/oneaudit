from oneaudit.api.leaks import LeaksProvider, PasswordHashDataFormat
import time


# https://hashmob.net/api/v2/documentation
class HashMobAPI(LeaksProvider):
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
        self.is_endpoint_enabled_for_cracking = self.is_endpoint_enabled and len(self.api_key) > 0
        self.is_endpoint_enabled = False
        self.request_args['headers']['api-key'] = self.api_key

    def fetch_plaintext_from_hash(self, crackable_hash):
        self.request_args['json']['hashes'] = [crackable_hash]
        cached, data = self.fetch_results_using_cache(crackable_hash)
        if 'data' not in data and 'found' not in data['data']:
            raise Exception(f"Unexpected answer for {self.api_name}: {data}")

        found = data['data']['found']

        # format is a INT so we can't return it too
        return cached, PasswordHashDataFormat(
            crackable_hash,
            None if len(found) == 0 else found[0]['plain'],
            None,
            False
        )

    def handle_rate_limit(self, response):
        time.sleep(300)

    # Minimum rate is "0.2" for 5 requests/second
    def get_rate(self):
        return 1