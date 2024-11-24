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
        import oneaudit.api.leaks.nth
        import oneaudit.api.leaks.whiteintel
        super().__init__([
            oneaudit.api.leaks.aura.AuraAPI(api_keys),
            oneaudit.api.leaks.hashmob.HashMobAPI(api_keys),
            oneaudit.api.leaks.hudsonrocks.HudsonRocksAPI(api_keys),
            oneaudit.api.leaks.leakcheck.LeakCheckAPI(api_keys),
            oneaudit.api.leaks.nth.NameThatHashAPI(api_keys),
            oneaudit.api.leaks.whiteintel.WhiteIntelAPI(api_keys)
        ])
        self.bcrypt_hash_regex = re.compile(r'(^\$2[aby]\$[0-9]{2}\$[A-Za-z0-9./]{22})')

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
        result['logins'].append(email)
        return self._call_method_on_each_provider(result, 'fetch_email_results', email)

    def investigate_hashes(self, login, data):
        uncracked_hashes = []
        if not data['passwords']:
            return data

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
                salt = match.group(1)
                for p in candidates:
                    known_hashes.append(bcrypt_hash(p, salt))
                if crackable_hash in known_hashes:
                    continue

            # Attempt to crack the hash
            result = PasswordHashDataFormat(value=crackable_hash, plaintext=None, format=None, format_confidence=-1)
            for provider in self.providers:
                if not provider.is_endpoint_enabled_for_cracking:
                    continue
                provider.logger.info(f"Attempting to crack hashes using {provider.api_name} (args={crackable_hash})")
                cached, api_result = provider.fetch_plaintext_from_hash(crackable_hash)
                if not cached:
                    self.trigger(provider.__class__.__name__, provider.get_rate())

                result = PasswordHashDataFormat(
                    crackable_hash,
                    api_result.plaintext if api_result.plaintext else result.plaintext,
                    api_result.format if result.format_confidence < api_result.format_confidence else result.format,
                    api_result.format_confidence if result.format_confidence < api_result.format_confidence else result.format_confidence,
                )

            # If uncracked, add the hash to the list, otherwise
            # Add the password to the list
            if result.plaintext is None:
                uncracked_hashes.append(result)
            else:
                data['passwords'].append(result.plaintext)

        data['hashes'] = uncracked_hashes
        del data['raw_hashes']

        return data

    def investigate_domain(self, domain):
        result = {
            'censored_data': [],
            'leaked_urls': [],
        }

        return result if domain is None else self._call_method_on_each_provider(result, 'fetch_domain_results', domain)


class LeaksProvider(oneaudit.api.DefaultProvider):
    def __init__(self, api_name, request_args, api_keys, show_notice=True):
        super().__init__(api_name, request_args, api_keys, show_notice)
        self.is_endpoint_enabled_for_cracking = False

    def fetch_email_results(self, email):
        yield True, {}

    def fetch_plaintext_from_hash(self, crackable_hash):
        return True, PasswordHashDataFormat(value=crackable_hash, plaintext=None, format=None)

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

@dataclasses.dataclass(frozen=True, order=False)
class BreachDataFormat:
    name: str
    source: str|None

    def to_dict(self):
        return {
            "name": self.name,
            "source": self.source,
        }

    def __lt__(self, other):
        if not isinstance(other, BreachDataFormat):
            return NotImplemented

        if self.name != other.name:
            return self.name < other.name

        return (self.source is not None, self.source) < (other.source is not None, other.source)

@dataclasses.dataclass(frozen=True, order=True)
class PasswordHashDataFormat:
    value: str
    plaintext: str|None
    format: str|None
    format_confidence: int

    def to_dict(self):
        return {
            "value": self.value,
            "format": self.format,
            "format_confidence": self.format_confidence,
        }