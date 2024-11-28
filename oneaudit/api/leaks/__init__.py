from dataclasses import dataclass
from enum import Enum


class LeaksAPICapability(Enum):
    INVESTIGATE_LEAKS_BY_EMAIL = 0
    INVESTIGATE_LEAKS_BY_DOMAIN = 1
    INVESTIGATE_CRACKED_HASHES = 2


@dataclass(frozen=True, order=True)
class PasswordHashDataFormat:
    value: str
    plaintext: str|None
    format: str|None
    format_confidence: int


@dataclass(frozen=True, order=True)
class InfoStealer:
    computer_name: str
    operating_system: str
    date_compromised: str

    def __post_init__(self):
        object.__setattr__(self, 'date_compromised', self.date_compromised[:10])
