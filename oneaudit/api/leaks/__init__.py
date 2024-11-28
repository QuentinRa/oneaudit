from dataclasses import dataclass
from enum import Enum


class LeaksAPICapability(Enum):
    INVESTIGATE_LEAKS_BY_EMAIL = 0
    INVESTIGATE_LEAKS_BY_DOMAIN = 1
    INVESTIGATE_CRACKED_HASHES = 2
    FREE_ENDPOINT = 3
    PAID_ENDPOINT = 4


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
class InfoStealer:
    computer_name: str
    operating_system: str
    date_compromised: str

    def __post_init__(self):
        object.__setattr__(self, 'date_compromised', self.date_compromised[:10])


@dataclass(frozen=True, order=False)
class BreachData:
    name: str
    source: str|None

    def to_dict(self):
        return {
            "name": self.name,
            "source": self.source if self.source else None,
        }

    def __lt__(self, other):
        if not isinstance(other, BreachData):
            return NotImplemented

        if self.name != other.name:
            return self.name < other.name

        return (self.source is not None, self.source) < (other.source is not None, other.source)

    def __hash__(self):
        normalized_source = self.source if self.source is not None else ''
        return hash((self.name, normalized_source))

    def __eq__(self, other):
        if not isinstance(other, BreachData):
            return NotImplemented
        return (self.name, self.source if self.source is not None else '') == (other.name, other.source if other.source is not None else '')
