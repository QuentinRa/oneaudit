from dataclasses import dataclass
from enum import Enum


class LeaksAPICapability(Enum):
    INVESTIGATE_LEAKS_BY_EMAIL = 0
    INVESTIGATE_LEAKS_BY_DOMAIN = 1
    INVESTIGATE_CRACKED_HASHES = 2


@dataclass(frozen=True, order=True)
class LeakTarget:
    login: str
    verified: bool
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
    computer_name: str
    operating_system: str
    date_compromised: str

    def __post_init__(self):
        object.__setattr__(self, 'date_compromised', self.date_compromised[:10])


@dataclass(frozen=True, order=False)
class BreachData:
    source: str
    date: str|None

    def to_dict(self):
        return {
            "source": self.source if self.source else "Unknown",
            "date": self.date[:7] if self.date else None,
        }

    def __lt__(self, other):
        if not isinstance(other, BreachData):
            return NotImplemented

        if self.source != other.source:
            return (self.source is not None, self.source) < (other.source is not None, other.source)

        return (self.date is not None, self.date[:7]) < (other.date is not None, other.date[:7])

    def __hash__(self):
        normalized_source =  self.date[:7] if self.date is not None else ''
        return hash((self.source, normalized_source))

    def __eq__(self, other):
        if not isinstance(other, BreachData):
            return NotImplemented
        return (self.source, self.date[:7] if self.date is not None else '') == (other.source, other.date[:7] if other.date is not None else '')
