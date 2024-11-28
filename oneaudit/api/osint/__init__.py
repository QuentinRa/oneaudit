import logging
import enum
import time
import typing
import dataclasses
from oneaudit.api.manager import OneAuditBaseAPIManager
from oneaudit.api.provider import OneAuditBaseProvider

class OSINTProviderManager(OneAuditBaseAPIManager):
    def __init__(self, api_keys, cache_only=False):
        import oneaudit.api.osint.rocketreach
        import oneaudit.api.osint.verifyemailaddress
        super().__init__([
            oneaudit.api.osint.rocketreach.RocketReachAPI(api_keys, cache_only),
            oneaudit.api.osint.verifyemailaddress.EmailVerifiedOnlineAPI(api_keys)
        ])

    def fetch_records(self, company_name):
        """
        Look for users and add them to a list of profiles
        """
        result = {}
        for provider in self.providers:
            result[provider.api_name] = []
        _, result = self._call_method_on_each_provider(result, 'fetch_targets_for_company', company_name)
        final_result = []
        for provider in self.providers:
            final_result.append(
                {
                    "source": provider.api_name,
                    "date": time.time(),
                    "version": 1.2,
                    "targets": result[provider.api_name]
                }
            )

        return final_result

    def export_records(self, source, profile_list_id):
        """
        Export entries from a platform list of profiles
        """
        for provider in self.providers:
            result = provider.export_records_from_profile(source, profile_list_id)
            if result:
                return result
        return []

    def parse_records(self, file_source, employee_filters, input_file):
        """
        Parse exported entries into a list of contacts.
        """
        result = []

        for provider in self.providers:
            try:
                result.append({
                    "source": provider.api_name,
                    "date": time.time(),
                    "version": 1.3,
                    "targets": provider.parse_records_from_file(file_source, employee_filters, input_file)
                })
            except Exception as e:
                logging.error(f"Error during parsing of {input_file} by {provider.api_name}: {e}")

        return result


class OSINTProvider(OneAuditBaseProvider):
    def __init__(self, request_args, api_name, api_keys, show_notice=True):
        super().__init__(api_name, request_args, api_keys, show_notice)

    def parse_records_from_file(self, file_source, employee_filters, input_file):
        return []

    def export_records_from_profile(self, source, profile_list_id):
        return []

    def fetch_targets_for_company(self, company_name):
        return []

    def is_email_valid(self, email):
        return True, OSINTScrappedEmailDataFormat(email, False)


class SocialNetworkEnum(enum.Enum):
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
    BADOO = "badoo"
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

        logging.getLogger("oneaudit").debug(f"The following value '{value}' is not within the supported social networks: IGNORED.")

        return None

@dataclasses.dataclass(frozen=True, order=True)
class OSINTScrappedDataFormat:
    full_name: str
    birth_year: str
    count: int
    links: typing.Dict[SocialNetworkEnum, str] = dataclasses.field(default_factory=dict)

    def to_dict(self):
        return {
            "full_name": self.full_name,
            "birth_year": self.birth_year,
            "count": self.count,
            "links": {k: v for k, v in self.links.items() if k},
        }


@dataclasses.dataclass(frozen=True, order=True)
class OSINTScrappedEmailDataFormat:
    email: str
    verified: bool


@dataclasses.dataclass(frozen=True, order=True)
class OSINTExportedDataFormat:
    first_name: str
    last_name: str
    emails: list[OSINTScrappedEmailDataFormat]
    links: typing.Dict[SocialNetworkEnum, str] = dataclasses.field(default_factory=dict)

    def to_dict(self):
        return {
            "first_name": self.first_name,
            "last_name": self.last_name,
            "emails": self.emails,
            "links": {k: v for k, v in self.links.items() if k},
        }
