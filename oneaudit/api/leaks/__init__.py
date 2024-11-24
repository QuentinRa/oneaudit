import oneaudit.api
import dataclasses
import hashlib
import bcrypt
import re


class LeaksProviderManager(oneaudit.api.DefaultProviderManager):
    def __init__(self, api_keys):
        import oneaudit.api.leaks.aura
        import oneaudit.api.leaks.hashmob
        import oneaudit.api.leaks.hudsonrocks
        import oneaudit.api.leaks.leakcheck
        import oneaudit.api.leaks.whiteintel
        super().__init__([
            oneaudit.api.leaks.aura.AuraAPI(api_keys),
            oneaudit.api.leaks.hashmob.HashMobAPI(api_keys),
            oneaudit.api.leaks.hudsonrocks.HudsonRocksAPI(api_keys),
            oneaudit.api.leaks.leakcheck.LeakCheckAPI(api_keys),
            oneaudit.api.leaks.whiteintel.WhiteIntelAPI(api_keys)
        ])
        self.bcrypt_hash_regex = re.compile(r'^\$2[aby]\$([0-9]{2})\$([A-Za-z0-9./]{22})')

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

    def append_data(self, email, result):
        return self._call_method_on_each_provider(result, 'fetch_email_results', email)

    def investigate_hashes(self, login, data):
        uncracked_hashes = []
        if not data['passwords']:
            return uncracked_hashes

        md5_sum = lambda p : hashlib.md5(p.encode()).hexdigest()
        sha1_sum = lambda p : hashlib.sha1(p.encode()).hexdigest()
        bcrypt_hash = lambda p, s : bcrypt.hashpw(p.encode(), s.encode())

        # We need to remove any hash for which we already have the passwords
        # We need to handle cases where the hash is just of checksum of the login
        # (as it happened multiple times for such hashes to be found, such as with gravatar leak, etc.)
        known_hashes = []
        candidates = [login] + data['passwords'] + data['logins']
        for p in candidates:
            known_hashes.append(md5_sum(p))
            known_hashes.append(sha1_sum(p))

        for crackable_hash in data['raw_hashes']:
            if crackable_hash in known_hashes:
                continue
            match = self.bcrypt_hash_regex.match(crackable_hash)
            if match:
                salt = match.group(2)
                for p in candidates:
                    known_hashes.append(bcrypt_hash(p, salt))
                if crackable_hash in known_hashes:
                    continue

            # Attempt to crack the hash
            print(crackable_hash)

            # If uncracked
            uncracked_hashes.append(crackable_hash)

        return uncracked_hashes

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