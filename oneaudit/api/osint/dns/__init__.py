from dataclasses import dataclass
from enum import Enum


class DNSCapability(Enum):
    SUBDOMAINS_ENUMERATION = 0


@dataclass(frozen=True, order=True)
class DomainInformation:
    domain_name: str
    ip_address: str
