from oneaudit.api.leaks import LeaksAPICapability, BreachData, deserialize_result
from oneaudit.api.leaks.provider import OneAuditLeaksAPIBulkProvider
from oneaudit.api.utils.caching import get_cached_result, set_cached_result


# https://documenter.getpostman.com/view/26427470/2s9Xy5MWUd
class HackCheck(OneAuditLeaksAPIBulkProvider):
    def _init_capabilities(self, api_key, api_keys):
        return [LeaksAPICapability.INVESTIGATE_LEAKS_BY_DOMAIN,
                LeaksAPICapability.INVESTIGATE_LEAKS_BY_EMAIL] if api_key is not None else []

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
        # To improve performances, we are caching parsed results
        cached_result_key = f'{self.api_name}_parsed_email_{email}'
        cached_result = get_cached_result(self.api_name, cached_result_key, do_not_expire=self.only_use_cache)

        if not cached_result:
            self.request_args['url'] = self.base_search_endpoint.format(type="email", value=email)
            cached, data = self.fetch_results_using_cache(f"search_email_{email}", default={'results': []})
            yield cached, {}

            if 'results' in data:
                result = None
                for raw_data in data['results']:
                    result = extract_data_from_result(raw_data, result)
                if not result:
                    result = {}
            else:
                result = deserialize_result(data['result'])

            if result:
                result['breaches'] = [
                    BreachData(clean_breach_source(breach.source), breach.date, breach.description)
                    for breach in result['breaches']
                ]

            # Save result after parsing
            cached_result = result
            if not self.only_use_cache:
                set_cached_result(self.api_name, cached_result_key, {
                    'result': result
                })
        else:
            cached_result = deserialize_result(cached_result['result'])

        yield True, cached_result


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
        indexor['passwords' if len(result['password']) < 32 else 'raw_hashes'].append(result['password'])
    if result['hash']:
        indexor['raw_hashes'].append(result['hash'])

    indexor['breaches'].append(BreachData(
        result['source']['name'],
        result['source']['date']
    ))
    return indexor

