from oneaudit.api.leaks import LeaksProvider
import time


# https://docs.snusbase.com/
class SnusbaseAPI(LeaksProvider):
    def __init__(self, api_keys):
        super().__init__(
            api_name='snusbase',
            request_args={
                'url': 'https://api.snusbase.com/data/search',
                'method': 'POST',
                'json': {
                    'types': ['email'],
                }
            },
            api_keys=api_keys,
            show_notice=False
        )
        self.request_args['headers']['Auth'] = self.api_key
        self.is_endpoint_enabled  = len(self.api_key) > 0 and self.api_key.startswith("sb")
        self.show_notice()

        self.known_keys = [
            'email', 'username', 'name', '_domain', 'url',
            'hash', 'password',
            'city', 'country', 'address', 'zip',
            'company', 'job',
            'created'
        ]

    def fetch_email_results(self, email):
        # Update parameters
        self.request_args['json']['terms'] = [email]
        # Send the request
        cached, data = self.fetch_results_using_cache(f"search_{email}")
        results = {
            'logins': [],
            'passwords': [],
            'censored_logins': [],
            'censored_passwords': [],
            'raw_hashes': [],
            'info_stealers': [],
            'breaches': [],
        }
        # city, country, zip, company, address, url
        for breach_data in data['results'].values():
            for entry in breach_data:
                for k, v in [
                    ('username', 'logins'),
                    ('name', 'logins'),
                    ('hash', 'raw_hashes'),
                    ('password', 'passwords'),
                ]:
                    if k in entry:
                        results[v].append(entry[k])
                for k in entry.keys():
                    if k not in self.known_keys:
                        raise Exception(f'{self.api_name}: Unknown key "{k}"')

        yield cached, {}


    def handle_rate_limit(self, response):
        time.sleep(60)

    def get_rate(self):
        return 0.5