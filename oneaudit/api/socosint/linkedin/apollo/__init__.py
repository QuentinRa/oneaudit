from oneaudit.api import APIRateLimitException
from oneaudit.api.osint import VerifiableEmail
from oneaudit.api.socosint import SocialNetworkEnum, UserProfileData
from oneaudit.api.socosint.linkedin.provider import OneAuditLinkedInAPIProvider
from oneaudit.api.socosint.linkedin import LinkedInAPICapability


class ApolloAPI(OneAuditLinkedInAPIProvider):
    def _init_capabilities(self, api_key, api_keys):
        return [
            LinkedInAPICapability.SEARCH_EMPLOYEES_BY_DOMAIN,
        ] if api_key is not None else []

    def __init__(self, api_keys):
        super().__init__(
            api_name='apollo',
            request_args={
                'url': 'https://nubela.co/proxycurl/api/linkedin/company/employees/',
                'method': 'GET',
                'params': {
                    'per_page': 100
                },
            },
            api_keys=api_keys,
        )
        self.request_args['headers']['x-api-key'] = self.api_key

    def search_employees_from_company_domain(self, company_domain, _, target_profile_list_id=None):
        self.request_args['url'] = 'https://api.apollo.io/api/v1/mixed_companies/search'
        self.request_args['params']['q_organization_domains'] = company_domain

        page = 1
        try:
            while True:
                self.logger.info(f"Querying page {page}/?")

                self.request_args['params']['page'] = page
                cached, results = self.fetch_results_using_cache(f"search_{company_domain}_page{page}", default={'contacts': [], 'pagination': {'total_pages': -1}},)
                yield cached, {}

                targets = []
                for employee in results['contacts']:
                    emails = []
                    if 'email' in employee:
                        if employee["email_status"] not in ["verified", "extrapolated"]:
                            self.logger.error(f"New value found for email_status: {employee['email_status']}")
                        emails.append(VerifiableEmail(
                            employee['email'],
                            employee["email_status"] == "verified"
                        ))
                    if employee['contact_emails']:
                        self.logger.error(f"Contact emails were not handled: {employee['contact_emails']}")

                    # noinspection PyTypeChecker
                    targets.append(UserProfileData(
                        employee["first_name"],
                        employee["last_name"],
                        emails,
                        {
                            enum_entry.name: employee[attribute_name]
                            for enum_entry, attribute_name in [
                                (SocialNetworkEnum.LINKEDIN, 'linkedin_url'),
                                (SocialNetworkEnum.TWITTER, 'twitter_url'),
                                (SocialNetworkEnum.FACEBOOK, 'facebook_url'),
                            ]
                            if attribute_name in employee and employee[attribute_name]
                        }
                    ))
                yield cached, { self.api_name: targets }

                pagination = results['pagination']
                if page >= pagination['total_pages']:
                    break
                page += 1
        except APIRateLimitException:
            pass
        except Exception as e:
            self.logger.error(f"Error received: {e}")

    def get_request_rate(self):
        return 2
