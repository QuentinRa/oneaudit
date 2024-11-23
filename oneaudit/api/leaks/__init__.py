import time
import requests
import oneaudit.api
import fake_useragent
import dataclasses


class LeaksProviderManager(oneaudit.api.DefaultProviderManager):
    def __init__(self, api_keys):
        import oneaudit.api.leaks.hudsonrocks
        import oneaudit.api.leaks.whiteintel
        super().__init__([
            oneaudit.api.leaks.hudsonrocks.HudsonRocksAPI(api_keys),
            oneaudit.api.leaks.whiteintel.WhiteIntelAPI(api_keys)
        ])

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
            if not provider.is_endpoint_enabled:
                continue
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
                if not provider.is_endpoint_enabled:
                    continue
                for cached, api_result in provider.fetch_domain_results(domain):
                    if not cached:
                        self.trigger(provider.__class__.__name__, provider.get_rate())
                    for k, v in api_result.items():
                        result[k].extend(v)

        for k, v in result.items():
            result[k] = sorted([e for e in set(v) if e])

        return result


class LeaksProvider(oneaudit.api.DefaultProvider):
    def fetch_email_results(self, email):
        yield True, {}

    def fetch_domain_results(self, domain):
        yield True, {}


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