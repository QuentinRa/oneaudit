from dataclasses import dataclass
from enum import Enum


class DNSCapability(Enum):
    SUBDOMAINS_ENUMERATION = 0
    FETCH_WILDCARD_DOMAINS = 1
    ASN_INVESTIGATION = 2

@dataclass(frozen=True)
class ASNInformation:
    asn_id: int
    asn_range: str
    asn_name: str

@dataclass(frozen=True)
class DomainInformation:
    domain_name: str
    ip_address: str|None
    asn: ASNInformation|None = None

    def __lt__(self, other):
        if not isinstance(other, DomainInformation):
            return NotImplemented

        if self.domain_name != other.domain_name:
            return (self.domain_name is not None, self.domain_name) < (other.domain_name is not None, other.domain_name)

        return (self.ip_address is not None, self.ip_address) < (other.ip_address is not None, other.ip_address)

    def __hash__(self):
        normalized_domain_name =  self.ip_address if self.ip_address is not None else ''
        return hash((self.domain_name, normalized_domain_name))

    def __eq__(self, other):
        if not isinstance(other, DomainInformation):
            return NotImplemented
        return (self.domain_name, self.ip_address if self.ip_address is not None else '') == (other.domain_name, other.ip_address if other.ip_address is not None else '')
