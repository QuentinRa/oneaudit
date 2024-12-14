from oneaudit.api import APIRateLimitException
from oneaudit.api.socosint.linkedin.provider import OneAuditLinkedInAPIProvider
from oneaudit.api.socosint.linkedin import LinkedInAPICapability


class NubelaProxycurlAPI(OneAuditLinkedInAPIProvider):
    def _init_capabilities(self, api_key, api_keys):
        return [
            LinkedInAPICapability.SEARCH_EMPLOYEES_BY_SOCIAL_NETWORK,
        ] if api_key is not None else []

    def __init__(self, api_keys):
        super().__init__(
            api_name='nubela',
            request_args={
                'method': 'GET',
                'url': 'https://nubela.co/proxycurl/api/contact-api/personal-email',
                'params': {}
            },
            api_keys=api_keys,
        )
        self.request_args['headers']['Authorization'] = f'Bearer {self.api_key}'

    def search_employees_by_social_network(self, linkedin, twitter, facebook):
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
                yield cached, { 'emails': [email.lower().strip() for email in result['emails'] if email.strip()] }
            except APIRateLimitException:
                pass

        yield True, {}

    def get_request_rate(self):
        return 10
