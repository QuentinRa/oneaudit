from oneaudit.api.manager import OneAuditBaseAPIManager
from oneaudit.api.socosint.linkedin import LinkedInAPICapability


class OneAuditLinkedInAPIManager(OneAuditBaseAPIManager):
    """
    APIs related to emails
    """
    def __init__(self, api_keys):
        from oneaudit.api.socosint.linkedin import rocketreach
        super().__init__([
            # FREE
            # FREEMIUM
            # PAID
            rocketreach.RocketReachAPI(api_keys)
        ])

    def search_employees_from_company_domain(self, company_domain, target_profile_list_id=None):
        _, result = self._call_all_providers_dict(
            heading='Searching employees',
            capability=LinkedInAPICapability.SEARCH_EMPLOYEES_BY_DOMAIN,
            stop_when_modified=False,
            method_name='search_employees_from_company_domain',
            result={provider.api_name: [] for provider in self.providers},
            args=(company_domain, target_profile_list_id)
        )
        return [entry for entries in result.values() for entry in entries]

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
