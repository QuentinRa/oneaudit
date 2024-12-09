from oneaudit.api import APIRateLimitException
from oneaudit.api.leaks import BreachData, LeaksAPICapability
from oneaudit.api.leaks.provider import OneAuditLeaksAPIProvider


# https://wiki.leakcheck.io/en/api
class LeakCheckFreeAPI(OneAuditLeaksAPIProvider):
    def _init_capabilities(self, api_key, api_keys):
        return [LeaksAPICapability.INVESTIGATE_LEAKS_BY_EMAIL] if api_key else []

    def get_request_rate(self):
        return 1

    def __init__(self, api_keys):
        super().__init__(
            api_name='leakcheck',
            request_args={
                'method': 'GET',
            },
            api_keys=api_keys
        )
        self.allowed_status_codes.append(400)

    def investigate_leaks_by_email(self, email, for_stats=False):
        # Update parameters
        self.request_args['url'] = 'https://leakcheck.io/api/public'
        self.request_args['params'] = {'check': email}
        # Send the request
        cached, data = self.fetch_results_using_cache(f"public_{email}", default={})
        sources = data['sources'] if 'sources' in data else []
        results = {
            'breaches': [BreachData(source["name"], source["date"] if "date" in source else None) for source in sources]
        }
        yield cached, results


class LeakCheckPaidAPI(OneAuditLeaksAPIProvider):
    def _init_capabilities(self, api_key, api_keys):
        return [LeaksAPICapability.INVESTIGATE_LEAKS_BY_EMAIL] if api_key else []

    def handle_rate_limit(self, response):
        if 'Limit reached' in response.text:
            self.logger.error(f"Provider was disabled due to rate-limit.")
            self.capabilities = []
            raise APIRateLimitException(f"{response.text}")

    def get_request_rate(self):
        return 1

    def __init__(self, api_keys):
        super().__init__(
            api_name='leakcheck_pro',
            request_args={
                'method': 'GET',
            },
            api_keys=api_keys
        )
        self.request_args['headers']['X-API-Key'] = self.api_key
        self.rate_limit_status_codes.append(403)
        self.allowed_status_codes.append(400)

    def investigate_leaks_by_email(self, email, for_stats=False):
        self.request_args['url'] = f'https://leakcheck.io/api/v2/query/{email}'
        try:
            cached, data = self.fetch_results_using_cache(f"{email}", default={'result': []})
            if 'result' not in data:
                if 'error' in data and data['error'] and 'Searching for government domains is disabled' in data['error']:
                    return False, {}
                raise Exception(f"Unexpected result for {self.api_name}: {data}")
            sources = [entry['source'] for entry in data['result'] if 'source' in entry]
            results = {
                'passwords': [entry['password'] for entry in data['result'] if 'password' in entry],
                'breaches': [BreachData(source["name"], source["breach_date"] if "breach_date" in source else None) for source in sources],
            }
            yield cached, results
        except APIRateLimitException:
            yield True, {}