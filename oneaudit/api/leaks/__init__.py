from dataclasses import dataclass
from enum import Enum


class LeaksAPICapability(Enum):
    INVESTIGATE_LEAKS_BY_EMAIL = 0
    INVESTIGATE_LEAKS_BY_DOMAIN = 1
    INVESTIGATE_CRACKED_HASHES = 2
    INVESTIGATE_BULK = 3
    INVESTIGATE_BREACH = 4


class LeakProviderUtilities(Enum):
    IMPORT_FROM_FILE = 0


@dataclass(frozen=True, order=True)
class LeakTarget:
    login: str
    verified: bool
    employed: bool
    emails: list[str]
    extra: dict


@dataclass(frozen=True, order=True)
class PasswordHashDataFormat:
    value: str
    plaintext: str|None
    format: str|None
    format_confidence: int


@dataclass(frozen=True, order=True)
class CensoredCredentials:
    censored_username: str
    censored_password: str


@dataclass(frozen=True, order=True)
class CensoredInfoStealers:
    device_identifier: str
    infection_date: str


@dataclass(frozen=True, order=True)
class CredentialStat:
    identifier: str
    provider: str


@dataclass(frozen=True, order=True)
class InfoStealer:
    computer_name: str|None
    operating_system: str|None
    date_compromised: str|None

    def __post_init__(self):
        object.__setattr__(self, 'computer_name', self.computer_name if self.computer_name else 'unknown')
        object.__setattr__(self, 'operating_system', self.operating_system if self.operating_system else 'unknown')
        object.__setattr__(self, 'date_compromised', self.date_compromised[:10] if self.date_compromised else 'unknown')


@dataclass(frozen=True, order=True)
class BreachData:
    source: str|None
    date: str|None
    description: str = ""

    def __post_init__(self):
        object.__setattr__(self, 'source', 'unknown' if self.source is None or not self.source.strip() else self.source.lower().strip())
        object.__setattr__(self, 'date', 'unknown' if self.date is None or not self.source.strip() else self.date[:7])

    def __str__(self):
        return f"{self.source} - {self.date}"

def deserialize_result(result):
    if 'breaches' in result:
        result['breaches'] = [BreachData(breach['source'], breach['date'], breach['description']) for breach in result['breaches']]
    if 'info_stealers' in result:
        result['info_stealers'] = [InfoStealer(stealer['computer_name'], stealer['operating_system'], stealer['date_compromised']) for stealer in result['info_stealers']]
    if 'hashes' in result:
        result['hashes'] = [PasswordHashDataFormat(h['value'], h['plaintext'], h['format'], h['format_confidence']) for h in result['hashes']]
    return result
