import time
import requests
import oneaudit.api
import fake_useragent
import dataclasses


class LeaksProviderManager:
    def __init__(self, api_keys):
        import oneaudit.api.leaks.hudsonrocks
        import oneaudit.api.leaks.whiteintel

        self.last_called = {}
        self.providers = [
            oneaudit.api.leaks.hudsonrocks.HudsonRocksAPI(api_keys),
            oneaudit.api.leaks.whiteintel.WhiteIntelAPI(api_keys)
        ]

    def trigger(self, handler, wait_time):
        now = time.time()
        last_called = self.last_called.get(handler, now)
        time_waited = now - last_called

        #print(f"Current time is {now}")
        #print(f"Last call to {handler} was at {last_called}: {time_waited}")

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
            for cached, api_result in provider.fetch_email_results(email):
                if not cached:
                    self.trigger(provider.__class__.__name__, provider.get_rate())
                for k, v in api_result.items():
                    result[k].extend(v)

        return result

    def investigate_domain(self, domain):
        result = {
            'censored_data': [],
            'leaked_urls': [],
        }

        if domain is not None:
            for provider in self.providers:
                for cached, api_result in provider.fetch_domain_results(domain):
                    if not cached:
                        self.trigger(provider.__class__.__name__, provider.get_rate())
                    for k, v in api_result.items():
                        result[k].extend(v)

        for k, v in result.items():
            result[k] = sorted([e for e in set(v) if e])

        return result


class LeaksProvider:
    def __init__(self, unique_identifier, request_args):
        self.unique_identifier = unique_identifier
        self.request_args = request_args
        if "headers" not in self.request_args:
            self.request_args["headers"] = {}
        self.request_args["headers"]['User-Agent'] = fake_useragent.UserAgent().random

    def fetch_email_results(self, email):
        yield True, {}

    def fetch_domain_results(self, domain):
        yield True, {}

    def fetch_results_using_cache(self, variable_key):
        cached = True
        cached_result_key = self.unique_identifier + variable_key
        data = oneaudit.api.get_cached_result(cached_result_key)
        if data is None:
            cached = False
            response = requests.request(**self.request_args)
            if response.status_code == 429:
                self.handle_rate_limit(response)
                return self.fetch_email_results(variable_key)

            if response.status_code == 401:
                print(f"[!] {self.__class__.__name__}: {response.text}")
                return True, {}

            if response.status_code not in [200]:
                print(self.__class__.__name__)
                print(response.text)
                print(response.status_code)
                raise Exception("This response code was not allowed/handled.")

            data = response.json()

            oneaudit.api.set_cached_result(cached_result_key, data)
        return cached, data

    def handle_rate_limit(self, response):
        pass

    def get_rate(self):
        return 5


@dataclasses.dataclass(frozen=True, order=True)
class InfoStealerLeakDataFormat:
    computer_name: str
    operating_system: str
    date_compromised: str

    def __post_init__(self):
        # Automatically called after the dataclass __init__ method.
        object.__setattr__(self, 'date_compromised', self.date_compromised[:10])

    def to_dict(self):
        return {
            "computer_name": self.computer_name,
            "operating_system": self.operating_system,
            "date_compromised": self.date_compromised
        }


@dataclasses.dataclass(frozen=True, order=True)
class CensoredCredentialsLeakDataFormat:
    censored_username: str
    censored_password: str

    def to_dict(self):
        return {
            "censored_username": self.censored_username,
            "censored_password": self.censored_password,
        }