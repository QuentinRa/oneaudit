from oneaudit.api.manager import OneAuditBaseAPIManager
from oneaudit.api.socosint import SocialNetworkEnum
from oneaudit.api.socosint.linkedin import rocketreach, nubela, apollo
from oneaudit.api.socosint.linkedin import LinkedInAPICapability
from oneaudit.utils.io import serialize_api_object


class OneAuditLinkedInAPIManager(OneAuditBaseAPIManager):
    """
    APIs related to emails
    """
    def __init__(self, api_keys):
        super().__init__([
            # FREE
            # FREEMIUM
            nubela.NubelaProxycurlAPI(api_keys),
            # PAID
            apollo.ApolloAPI(api_keys),
            rocketreach.RocketReachAPI(api_keys),
        ])

    def search_employees_from_company_domain(self, company_domain, company_profile, target_profile_list_id=None):
        _, result = self._call_all_providers_dict(
            heading='Searching employees',
            capability=LinkedInAPICapability.SEARCH_EMPLOYEES_BY_DOMAIN,
            stop_when_modified=False,
            method_name='search_employees_from_company_domain',
            result={provider.api_name: [] for provider in self.providers},
            args=(company_domain, company_profile, target_profile_list_id)
        )
        entries = [entry for entries in result.values() for entry in entries]

        final_entries = []
        for entry in entries:
            args = (
                entry.links[SocialNetworkEnum.LINKEDIN.name] if SocialNetworkEnum.LINKEDIN.name in entry.links else None,
                entry.links[SocialNetworkEnum.TWITTER.name] if SocialNetworkEnum.TWITTER.name in entry.links else None,
                entry.links[SocialNetworkEnum.FACEBOOK.name] if SocialNetworkEnum.FACEBOOK.name in entry.links else None,
            )
            _, result = self._call_all_providers_dict(
                heading='Searching employees emails',
                capability=LinkedInAPICapability.SEARCH_EMPLOYEES_BY_SOCIAL_NETWORK,
                stop_when_modified=False,
                method_name='search_employees_by_social_network',
                result=serialize_api_object(entry),
                args=args
            )
            final_entries.append(result)

        return final_entries

    def export_profiles_from_profile_list(self, api_name, target_profile_list_id):
        for provider in self.providers:
            if provider.api_name == api_name:
                return provider.export_profiles_from_profile_list(target_profile_list_id)
        raise Exception(f"Invalid {api_name} given to export_profiles_from_profile_list")

    def parse_records_from_export(self, api_name, employee_filters, input_file):
        for provider in self.providers:
            if provider.api_name == api_name:
                return provider.parse_records_from_export(employee_filters, input_file)
        raise Exception(f"Invalid {api_name} given to parse_records_from_export")
