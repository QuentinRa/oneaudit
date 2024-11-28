from oneaudit.api import APIRateLimitException
from oneaudit.api.leaks import LeaksAPICapability
from oneaudit.api.leaks.provider import OneAuditLeaksAPIProvider, PasswordHashDataFormat
from time import sleep


# https://docs.snusbase.com/
class SnusbaseAPI(OneAuditLeaksAPIProvider):
    def _init_capabilities(self, api_key, api_keys):
        return [LeaksAPICapability.INVESTIGATE_LEAKS_BY_EMAIL, LeaksAPICapability.INVESTIGATE_CRACKED_HASHES] if api_key is not None else []

    def handle_rate_limit(self, response):
        if 'Rate-limit exceeded.' in response.text:
            self.logger.error(f"Provider {self.api_name} was disabled due to rate-limit on search.")
            self.capabilities.remove(LeaksAPICapability.INVESTIGATE_LEAKS_BY_EMAIL)
            raise APIRateLimitException(f"{response.text}")
        else:
            sleep(2)

    def get_request_rate(self):
        return 0.5

    def __init__(self, api_keys):
        super().__init__(
            api_name='snusbase',
            request_args={
                'method': 'POST',
                'json': {}
            },
            api_keys=api_keys
        )
        self.request_args['headers']['Auth'] = self.api_key
        self.known_keys = [
            'email', 'username', 'name', 'id', 'uid', 'created', 'updated',
            '_domain', 'url', 'followers',
            'hash', 'salt', 'password', 'lastip', 'regip', 'host',
            'city', 'country', 'state', 'address', 'zip', 'birthdate', 'language', 'phone',
            'company', 'job', 'gender', 'other', 'unparsed', 'regdate', 'date'
        ]
        self.api_endpoint = 'https://api.snusbase.com/{route}'
        self.rate_limit_status_codes = [429, 502]

    def investigate_leaks_by_email(self, email):
        # Update parameters
        self.request_args['url'] = self.api_endpoint.format(route='data/search')
        self.request_args['json']['terms'] = [email]
        self.request_args['json']['types'] = ['email']
        # Send the request
        try:
            cached, data = self.fetch_results_using_cache(f"search_{email}")
            results = {
                'logins': [],
                'passwords': [],
                'raw_hashes': []
            }
            # city, country, zip, company, address, url
            for breach_data in data['results'].values():
                results['verified'] = True
                for entry in breach_data:
                    for k, v in [
                        ('username', 'logins'),
                        ('name', 'logins'),
                        ('password', 'passwords'),
                        ('hash', 'raw_hashes'),
                    ]:
                        if k in entry:
                            results[v].append(entry[k])

                    for k in entry.keys():
                        if k not in self.known_keys:
                            raise Exception(f'{self.api_name}: Unknown key "{k}" with value "{entry[k]}" for "{email}"')

            yield cached, results
        except APIRateLimitException:
            yield True, {}

    def lookup_plaintext_from_hash(self, crackable_hash):
        # Update parameters
        self.request_args['url'] = self.api_endpoint.format(route='tools/hash-lookup')
        self.request_args['json']['terms'] = [crackable_hash]
        self.request_args['json']['types'] = ['hash']

        cached, data = self.fetch_results_using_cache(crackable_hash)
        passwords = [entry['password'] for breach_data in data['results'].values() for entry in breach_data if 'password' in entry]

        return cached, PasswordHashDataFormat(
            value=crackable_hash,
            plaintext=None if not passwords else passwords[0],
            format=None,
            format_confidence=-1
        )