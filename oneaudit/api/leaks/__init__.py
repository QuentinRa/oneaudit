import oneaudit.api
import dataclasses


class LeaksProviderManager(oneaudit.api.DefaultProviderManager):
    def __init__(self, api_keys):
        import oneaudit.api.leaks.aura
        import oneaudit.api.leaks.hudsonrocks
        import oneaudit.api.leaks.leakcheck
        import oneaudit.api.leaks.whiteintel
        super().__init__([
            oneaudit.api.leaks.aura.AuraAPI(api_keys),
            oneaudit.api.leaks.hudsonrocks.HudsonRocksAPI(api_keys),
            oneaudit.api.leaks.leakcheck.LeakCheckAPI(api_keys),
            oneaudit.api.leaks.whiteintel.WhiteIntelAPI(api_keys)
        ])

    def get_base_data(self):
        return {
            'logins': [],
            'passwords': [],
            'censored_logins': [],
            'censored_passwords': [],
            'raw_hashes': [],
            'info_stealers': [],
            'breaches': [],
        }

    def append_data(self, email, current):
        result = {
            'logins': current['logins'],
            'passwords': current['passwords'],
            'censored_logins': current['censored_logins'],
            'censored_passwords': current['censored_passwords'],
            'raw_hashes': current['raw_hashes'],
            'info_stealers': current['info_stealers'],
            'breaches': current['breaches'],
        }

        return self._call_method_on_each_provider(result, 'fetch_email_results', email)

    def investigate_domain(self, domain):
        result = {
            'censored_data': [],
            'leaked_urls': [],
        }

        return result if domain is None else self._call_method_on_each_provider(result, 'fetch_domain_results', domain)


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

@dataclasses.dataclass(frozen=True, order=True)
class BreachDataFormat:
    name: str
    source: str

    def to_dict(self):
        return {
            "name": self.name,
            "source": self.source,
        }