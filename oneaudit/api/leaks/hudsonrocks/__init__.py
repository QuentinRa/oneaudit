from oneaudit.api.leaks import LeaksProvider, InfoStealerLeakDataFormat
import time


# https://cavalier.hudsonrock.com/docs
class HudsonRocksAPI(LeaksProvider):
    def __init__(self, api_keys):
        super().__init__(
            api_name='hudsonrocks',
            unique_identifier='hudsonrocks_free_',
            request_args={
                'method': 'GET',
                'url': 'https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email',
            },
            api_keys=api_keys
        )

    def fetch_email_results(self, email):
        # Update parameters
        self.request_args['params'] = {'email': email}
        # Send the request
        cached, data = self.fetch_results_using_cache(email)
        result = {
            'info_stealers': [],
            'censored_logins': [],
            'censored_passwords': [],
        }
        for stealer in data['stealers']:
            result['info_stealers'].append(InfoStealerLeakDataFormat(
                stealer['computer_name'],
                stealer['operating_system'],
                stealer['date_compromised'],
            ))
            result['censored_logins'].extend(stealer['top_logins'])
            result['censored_passwords'].extend(stealer['top_passwords'])

        yield cached, result

    def handle_rate_limit(self, response):
        time.sleep(60)

    # Minimum rate is "0.2" for 5 requests/second
    def get_rate(self):
        return 0.5