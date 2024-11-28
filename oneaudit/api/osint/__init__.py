from dataclasses import dataclass


@dataclass(frozen=True, order=True)
class VerifiableEmail:
    """An email that may have been verified or not"""
    email: str
    verified: bool