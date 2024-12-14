from oneaudit.api.leaks import LeaksAPICapability, BreachData, deserialize_result
from oneaudit.api.leaks.provider import OneAuditLeaksAPIBulkProvider


# https://documenter.getpostman.com/view/26427470/2s9Xy5MWUd
class HackCheck(OneAuditLeaksAPIBulkProvider):
    def _init_capabilities(self, api_key, api_keys):
        return [LeaksAPICapability.INVESTIGATE_LEAKS_BY_DOMAIN, LeaksAPICapability.INVESTIGATE_LEAKS_BY_EMAIL] if api_key is not None else []

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

    def investigate_leaks_by_domain(self, domain):
        self.request_args['url'] = self.base_search_endpoint.format(type="domain", value=domain)
        cached, results = self.fetch_results_using_cache(f"search_domain_{domain}", default={'results': []})

        if "pagination" in results:
            raise Exception(f"Pagination is not handled yet for {self.api_name}...\nReceived {results['pagination']} for {domain}.")

        indexed_data = {}
        for result in results['results']:
            email = result['email'].lower().strip()
            if ',' in email:
                email = [email for email in email.split(',') if email.endswith(domain)]
                if len(email) == 1:
                    email = email[0]
                else:
                    self.logger.error(f"Could not find email for {result}")
                    continue

            indexed_data[email] = extract_data_from_result(result, indexed_data[email] if email in indexed_data else None)

        self._cache_indexed_data_if_required("search_email_{key}", indexed_data)

        yield cached, {
            'emails': list(indexed_data.keys())
        }

    def investigate_leaks_by_email(self, email, for_stats=False):
        self.request_args['url'] = self.base_search_endpoint.format(type="email", value=email)
        cached, data = self.fetch_results_using_cache(f"search_email_{email}", default={'results': []})

        # Prepare result. We want to tune breach names a bit
        result = None
        if 'results' in data:
            for raw_data in data['results']:
                result = extract_data_from_result(raw_data, result)

            if not result:
                return cached, {}
        else:
            result = deserialize_result(data['result'])

        result['breaches'] = [
            BreachData(clean_breach_source(breach.source), breach.date, breach.description)
            for breach in result['breaches']
        ]
        yield cached, result


def clean_breach_source(breach_source):
    return breach_source.replace("-scrape", "") if breach_source else None


def extract_data_from_result(result, indexor):
    if indexor is None:
        indexor = {
            "logins": [],
            "passwords": [],
            "raw_hashes": [],
            "breaches": [],
        }

    if result['username']:
        indexor['logins'].append(result['username'])
    if result['password']:
        indexor['passwords'].append(result['password'])
    if result['hash']:
        indexor['raw_hashes'].append(result['hash'])

    indexor['breaches'].append(BreachData(
        result['source']['name'],
        result['source']['date']
    ))
    return indexor

