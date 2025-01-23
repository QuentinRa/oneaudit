from dataclasses import field, dataclass
from oneaudit.api.osint import VerifiableEmail
from oneaudit.utils.logs import get_project_logger
from enum import Enum
from typing import Dict


class SocialNetworkEnum(Enum):
    LINKEDIN = "linkedin"
    TWITTER = "twitter"
    FACEBOOK = "facebook"
    PINTEREST = "pinterest"
    INSTAGRAM = "instagram"
    YOUTUBE = "youtube"

    GITHUB = "github"
    STACKOVERFLOW = "stackoverflow"
    MEDIUM = "medium"
    AMAZON = "amazon"
    GRAVATAR = "gravatar"

    def get(value):
        for match, key in [("linkedin.com", "linkedin")]:
            if match in value:
                value = key
                break
        value = value.split(".")[0]

        for name, member in SocialNetworkEnum.__members__.items():
            if member.value == value:
                return name

        get_project_logger().debug(f"The following value '{value}' is not within the supported social networks: IGNORED.")

        return None


@dataclass(frozen=True, order=True)
class UserProfileRawData:
    full_name: str
    birth_year: str
    emails: list[str]
    links: Dict[SocialNetworkEnum, str] = field(default_factory=dict)

    def to_dict(self):
        return {
            "full_name": self.full_name,
            "birth_year": self.birth_year,
            "emails": self.emails,
            "links": {k: v for k, v in self.links.items() if k},
        }


@dataclass(frozen=True, order=True)
class UserProfileData:
    first_name: str
    last_name: str
    current_title: str
    current_company: str
    emails: list[VerifiableEmail]
    links: Dict[SocialNetworkEnum, str] = field(default_factory=dict)

    def to_dict(self):
        return {
            "first_name": self.first_name,
            "last_name": self.last_name,
            "current_title": self.current_title,
            "current_company": self.current_company,
            "emails": self.emails,
            "links": {k: v for k, v in self.links.items() if k},
        }
