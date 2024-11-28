from oneaudit.api.manager import OneAuditBaseAPIManager
from oneaudit.api.socosint.linkedin import LinkedInAPICapability
from time import time

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

        return [{
            "source": provider.api_name,
            "date": time(),
            "version": 1.2,
            "targets": result[provider.api_name]
        } for provider in self.providers]

