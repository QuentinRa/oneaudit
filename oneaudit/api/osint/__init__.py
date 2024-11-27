import logging
import enum
import time
import typing
import dataclasses
import oneaudit.api

class OSINTProviderManager(oneaudit.api.DefaultProviderManager):
    def __init__(self, api_keys, cache_only=False):
        import oneaudit.api.osint.rocketreach
        import oneaudit.api.osint.verifyemailaddress
        super().__init__([
            oneaudit.api.osint.rocketreach.RocketReachAPI(api_keys, cache_only),
            oneaudit.api.osint.verifyemailaddress.VerifyEmailAddressAPI(api_keys, cache_only)
        ])

    def export_records(self, source, profile_list_id):
        for provider in self.providers:
            result = provider.export_records_from_profile(source, profile_list_id)
            if result:
                return result
        return []

    def parse_records(self, file_source, employee_filter, input_file):
        result = []

        for provider in self.providers:
            try:
                result.append({
                    "source": provider.api_name,
                    "date": time.time(),
                    "version": 1.3,
                    "targets": provider.parse_records_from_file(file_source, employee_filter, input_file)
                })
            except Exception as e:
                logging.error(f"Error during parsing of {input_file} by {provider.api_name}: {e}")

        return result

    def fetch_records(self, company_name):
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

    # For emails, we will not use providers because we only have one email checker.
    def get_single_email(self, single_email):
        result = []
        answer = self.verify_one_email(single_email)
        result_api = False
        if answer == "exists":
            result_api = True
        elif answer == "error_http":
            logging.error(f"Error while verifying {single_email}: {e}")
        result.append(OSINTScrappedEmailDataFormat(
                single_email.lower(),
                result_api
            )
        )
    
    def get_mulitple_email(self, email_list):
        # email_list est déjà ouvert
        result = []
        
        for line in mail_list:
            mail = line.strip()
            result.append(get_single_email(mail))

        return result



class OSINTProvider(oneaudit.api.DefaultProvider):
    def __init__(self, request_args, api_name, api_keys, show_notice=True):
        super().__init__(api_name, request_args, api_keys, show_notice)

    def parse_records_from_file(self, file_source, employee_filter, input_file):
        return []

    def export_records_from_profile(self, source, profile_list_id):
        return []

    def fetch_targets_for_company(self, company_name):
        return []
    
    def verify_one_email(self, mail_string):
        return []


class SocialNetworkEnum(enum.Enum):
    LINKEDIN = "linkedin"
    TWITTER = "twitter"
    FACEBOOK = "facebook"
    PINTEREST = "pinterest"

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

    def to_dict(self):
        return {
            "email": self.email,
            "verified": self.verified,
        }