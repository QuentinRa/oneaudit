from oneaudit.api.leaks import LeaksAPICapability
from oneaudit.api.leaks.provider import OneAuditLeaksAPIBulkProvider


# https://haveibeenpwned.com/API/v3#AllBreaches
class HaveIBeenPwnedFree(OneAuditLeaksAPIBulkProvider):
    def _init_capabilities(self, api_key, api_keys):
        return [LeaksAPICapability.INVESTIGATE_BULK, LeaksAPICapability.INVESTIGATE_BREACH] if api_key is not None else []

    def get_request_rate(self):
        return 2

    def __init__(self, api_keys):
        super().__init__(
            api_name='haveibeenpwned',
            request_args={
                'method': 'GET',
                'url': 'https://haveibeenpwned.com/api/v3/breaches',
            },
            api_keys=api_keys
        )

    def investigate_bulk(self, _):
        cached, results = self.fetch_results_using_cache("breaches", default=[])
        indexed_data = {}
        for result in results:
            domain = result['Domain'].lower().strip()
            if not domain:
                domain = result['Name'].lower().strip()

            if domain not in indexed_data:
                indexed_data[domain] = []
            indexed_data[domain].append({
                'domain': domain,
                'title': result['Title'].lower().strip(),
                'name': result['Name'].lower().strip(),
                'date': result['BreachDate'],
                'scope': result['PwnCount'],
                'description': result['Description'],
            })

        self._cache_indexed_data_if_required("breach_data_{key}", indexed_data)

        yield cached, {}

    def investigate_breach_from_name(self, breach):
        raise Exception(breach)
