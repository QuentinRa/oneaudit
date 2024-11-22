import time
import requests
import oneaudit.api


class LeaksProviderManager:
    def __init__(self, api_keys):
        import oneaudit.api.leaks.hudsonrocks

        self.last_called = {}
        self.providers = [
            oneaudit.api.leaks.hudsonrocks.HudsonRocksAPI(api_keys)
        ]

    def trigger(self, handler, wait_time):
        now = time.time()
        last_called = self.last_called.get(handler, now)
        time_waited = now - last_called

        print(f"Current time is {now}")
        print(f"Last call to {handler} was at {last_called}: {time_waited}")

        if time_waited < wait_time:
            time_to_wait = wait_time - time_waited
            print(f"We need to wait {time_to_wait}")
            time.sleep(time_to_wait)

        self.last_called[handler] = time.time()

    def get_base_data(self):
        return {
            'passwords': [],
            'censored_logins': [],
            'censored_passwords': [],
            'hashes': [],
            'info_stealers': [],
        }

    def append_data(self, email, current):
        result = {
            'passwords': current['passwords'],
            'censored_logins': current['censored_logins'],
            'censored_passwords': current['censored_passwords'],
            'hashes': current['hashes'],
            'info_stealers': current['info_stealers'],
        }

        for provider in self.providers:
            cached, api_result = provider.fetch_results(email)
            if not cached:
                self.trigger(provider.__class__.__name__, provider.get_rate())
            for k, v in api_result.items():
                result[k].extend(v)

        return result


class LeaksProvider:
    def __init__(self, unique_identifier, request_args):
        self.unique_identifier = unique_identifier
        self.request_args = request_args

    def fetch_results(self, email):
        return False, {}

    def fetch_results_using_cache(self, email):
        cached = True
        cached_result_key = self.unique_identifier + email
        data = oneaudit.api.get_cached_result(cached_result_key)
        if data is None:
            cached = False
            response = requests.request(**self.request_args)
            if response.status_code == 429:
                self.handle_rate_limit(response)
                return self.fetch_results(email)
            data = response.json()
            oneaudit.api.set_cached_result(cached_result_key, data)
        return cached, data

    def handle_rate_limit(self, response):
        pass

    def get_rate(self):
        return 5