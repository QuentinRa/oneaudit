from oneaudit.api.leaks import LeaksProvider
from oneaudit.api import get_cached_result, set_cached_result

import time
import requests

# https://cavalier.hudsonrock.com/docs
class HudsonRocksAPI(LeaksProvider):
    def __init__(self, _):
        pass

    def fetch_results(self, email):
        cached = True
        cached_result_key = "hudsonrocks_free_" + email
        data = get_cached_result(cached_result_key)
        if data is None:
            cached = False
            response = requests.get(
                url='https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email',
                params={
                    'email': email
                }
            )
            if response.status_code == 429:
                time.sleep(60)
                return self.fetch_results(email)
            data = response.json()
            set_cached_result(cached_result_key, data)

        result = {
            'info_stealers': [],
            'censored_logins': [],
            'censored_passwords': [],
        }
        for stealer in data['stealers']:
            result['info_stealers'].append({
                "computer_name": stealer['computer_name'],
                "operating_system": stealer['operating_system'],
                "date_compromised": stealer['date_compromised'],
            })
            result['censored_logins'].extend(stealer['top_logins'])
            result['censored_passwords'].extend(stealer['top_passwords'])

        return cached, result

    # Minimum rate is "0.2" for 5 requests/second
    def get_rate(self):
        return 0.5