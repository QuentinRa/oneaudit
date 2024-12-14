from oneaudit.api import APIRateLimitException
from oneaudit.api.osint import VerifiableEmail
from oneaudit.api.socosint import SocialNetworkEnum, UserProfileData
from oneaudit.api.socosint.linkedin.provider import OneAuditLinkedInAPIProvider
from oneaudit.api.socosint.linkedin import LinkedInAPICapability
from urllib.parse import parse_qs


class NubelaProxycurlAPI(OneAuditLinkedInAPIProvider):
    def _init_capabilities(self, api_key, api_keys):
        return [
            LinkedInAPICapability.SEARCH_EMPLOYEES_BY_DOMAIN,
            LinkedInAPICapability.SEARCH_EMPLOYEES_BY_SOCIAL_NETWORK,
        ] if api_key is not None else []

    def __init__(self, api_keys):
        super().__init__(
            api_name='nubela',
            request_args={
                'method': 'GET',
                'params': {}
            },
            api_keys=api_keys,
        )
        self.request_args['headers']['Authorization'] = f'Bearer {self.api_key}'
        self.rate_limit_status_codes = [403, 429]

    def search_employees_from_company_domain(self, company_domain, company_profile, target_profile_list_id=None):
        if not company_profile:
            return True, {}

        self.request_args['url'] = 'https://nubela.co/proxycurl/api/linkedin/company/employees/'
        self.request_args['params'] = {
            'url': company_profile,
            'coy_name_match': 'include',
            'use_cache': 'if-recent',
            'enrich_profiles': 'enrich',
            'page_size': 10,
            'employment_status': 'current',
        }

        page = 0
        try:
            while True:
                self.logger.info(f"Querying page {page + 1}/?")

                cached, results = self.fetch_results_using_cache(f"search_{company_domain}_page{page}", default={'employees': [], 'next_page': None })
                yield cached, {}

                targets = []
                for employee in results['employees']:
                    targets.append(UserProfileData(
                        employee['profile']["first_name"],
                        employee['profile']["last_name"],
                        [],
                        {
                            SocialNetworkEnum.LINKEDIN.name: employee['profile_url']
                        }
                    ))
                yield cached, { self.api_name: targets }

                after_value = parse_qs(results['next_page']).get('after', None) if results['next_page'] else None
                if not after_value:
                    break
                self.request_args['params']['after'] = after_value[0]
                page += 1
        except APIRateLimitException:
            pass
        except Exception as e:
            self.logger.error(f"Error received: {e}")

    def search_employees_by_social_network(self, linkedin, twitter, facebook):
        self.request_args['url'] = 'https://nubela.co/proxycurl/api/contact-api/personal-email'
        for (param, value) in [('twitter_profile_url', twitter),
                               ('linkedin_profile_url', linkedin),
                               ('facebook_profile_url', facebook)]:
            if not value:
                continue
            self.request_args['params'] = {
                param: value,
                'email_validation': 'fast',
                'page_size': '0',
            }
            try:
                cached, result = self.fetch_results_using_cache(value, default={'emails': []})
                yield cached, { 'emails': [VerifiableEmail(email.lower().strip(), True) for email in result['emails'] if email.strip()] }
            except APIRateLimitException:
                pass

        yield True, {}

    def get_request_rate(self):
        return 3
