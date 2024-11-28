from oneaudit.api.provider import OneAuditBaseProvider


class OneAuditLinkedInAPIProvider(OneAuditBaseProvider):
    """
    Implementation of an API related to emails.
    """
    def __init__(self, api_name, request_args, api_keys):
        super().__init__(api_name, request_args, api_keys)

    def search_employees_from_company_domain(self, company_domain, target_profile_list_id=None):
        """
        Each API will return a list of employees
        """
        yield True, { self.api_name: [] }

    def export_profiles_from_profile_list(self, target_profile_list_id):
        """
        Export as JSON profiles from a profile list
        """
        return []

    def parse_records_from_export(self, employee_filters, input_file):
        """
        Parse an export of JSON profiles (as results can be exported using multiple means aside from the script,
        such as using webhook, or the website for RocketReach).
        """
        return []