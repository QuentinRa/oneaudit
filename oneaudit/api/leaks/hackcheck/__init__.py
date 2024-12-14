from oneaudit.api.leaks import LeaksAPICapability, BreachData
from oneaudit.api.leaks.provider import OneAuditLeaksAPIBulkProvider


# https://documenter.getpostman.com/view/26427470/2s9Xy5MWUd
class HackCheck(OneAuditLeaksAPIBulkProvider):
    def _init_capabilities(self, api_key, api_keys):
        return [
                LeaksAPICapability.INVESTIGATE_LEAKS_BY_DOMAIN,
                ] if api_key is not None else []

    def get_request_rate(self):
        return 1

    def __init__(self, api_keys):
        super().__init__(
            api_name='hackcheck',
            request_args={
                'method': 'GET',
            },
            api_keys=api_keys
        )
        self.base_search_endpoint = f'https://api.hackcheck.io/search/{self.api_key}/{{type}}/{{value}}'

    def investigate_bulk(self, emails):
        yield True, {}

    def investigate_leaks_by_domain(self, domain):
        self.request_args['url'] = self.base_search_endpoint.format(type="domain", value=domain)
        cached, results = self.fetch_results_using_cache(f"search_domain_{domain}", default={'results': []})

        indexed_data = {}
        for result in results['results']:
            email = result['email'].lower().strip()
            if email not in indexed_data:
                indexed_data[email] = {
                    "logins": [],
                    "passwords": [],
                    "raw_hashes": [],
                    "breaches": [],
                }
            if result['username']:
                indexed_data[email]['logins'].append(result['username'])
            if result['password']:
                indexed_data[email]['passwords'].append(result['password'])
            if result['hash']:
                indexed_data[email]['raw_hashes'].append(result['hash'])

            indexed_data[email]['breaches'].append(BreachData(
                result['source']['name'],
                result['source']['date']
            ))

        self._cache_indexed_data_if_required("search_email_{key}", indexed_data)

        yield cached, {}
