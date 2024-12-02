from oneaudit.api.utils.caching import get_cached_result, set_cached_result
from oneaudit.api.leaks import LeaksAPICapability, BreachData
from oneaudit.api.leaks.provider import OneAuditLeaksAPIProvider
from time import sleep
from base64 import b64encode


# https://docs.enzoic.com/enzoic-api-developer-documentation
class EnzoicAPI(OneAuditLeaksAPIProvider):
    def _init_capabilities(self, api_key, api_keys):
        return [LeaksAPICapability.INVESTIGATE_LEAKS_BY_EMAIL, LeaksAPICapability.INVESTIGATE_BULK] if api_key is not None else []

    def handle_rate_limit(self, response):
        sleep(30)

    def get_request_rate(self):
        return 1

    def __init__(self, api_keys):
        super().__init__(
            api_name='enzoic',
            request_args={
                'method': 'GET',
                'url': 'https://api.enzoic.com/v1/exposures-for-usernames',
                'params': {
                    'includeExposureDetails': 1
                }
            },
            api_keys=api_keys
        )
        self.request_args['headers']['authorization'] = f'basic {b64encode(self.api_key.encode()).decode()}' if self.api_key else ''
        self.exposure_key_format = f'{self.api_name}_exposures_{{email}}'

    def investigate_bulk(self, emails):
        # Only process the emails for which we don't have anything
        emails = sorted([email for email in emails if get_cached_result(self.api_name, self.exposure_key_format.format(email=email)) is None])
        print(len(emails))
        for i in range(0, len(emails), 50):
            self.request_args['params']['usernames'] = emails[i:i+50]
            data = self.fetch_result_without_cache()
            for entry in data:
                email = entry['username']
                set_cached_result(self.api_name, self.exposure_key_format.format(email=email), entry)
            yield False, {}
        yield True, {}

    def investigate_leaks_by_email(self, email):
        # We are using bulk requests, so we mustn't process individual requests
        self.only_use_cache = True
        # Retrieve from cache
        _, data = self.fetch_results_using_cache(f"exposures_{email}", default={'exposures': []})
        result = { 'breaches': [] }
        for exposure in data['exposures']:
            source = exposure['sourceURLs'][0] if exposure['sourceURLs'] else None
            # if not sources:
            #     sources = [exposure['title']]
            # if sources:
            #     sources[0] = sources[0].lower()
            #     sources[0] = (
            #         'stealer logs' if 'infostealers' in sources[0] else
            #         'combolist' if 'combolist' in sources[0] or 'compilation' in sources[0] or 'collection' in sources[0] else
            #         'combolist' if 'dehashed' in sources[0] or 'fabricated' in sources[0] or 'cit0day' in sources[0] else
            #         sources[0] if 'threat actor comms file download' not in sources[0] and 'unknown' not in sources[0] else 'unknown'
            #     )
            # if source and len(source) > 20:
            #     raise Exception(f'{self.api_name}: unexpected source "{source}" for "{exposure}".')
            result['breaches'].append(BreachData(
                source,
                exposure['dateAdded']
            ))
        yield True, result
