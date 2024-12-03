from oneaudit.api.utils.caching import get_cached_result, set_cached_result
from oneaudit.api.leaks import LeaksAPICapability, BreachData
from oneaudit.api.leaks.provider import OneAuditLeaksAPIProvider
from dataclasses import asdict
from time import sleep
from base64 import b64encode
from re import compile


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
        self.domain_matcher = compile(r'([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(\.[a-zA-Z]{2,})?')
        self.title_mapper = {
            'Threat Actor': None,
            'Unknown': None,

            'Infostealers': 'Stealer Logs',

            'collection #': None,
        }

    def investigate_bulk(self, emails):
        # We don't have anything to do without caching
        if self.only_use_cache:
            return True, {}

        # Only process the emails for which we don't have anything
        emails = sorted([email for email in emails if get_cached_result(self.api_name, self.exposure_key_format.format(email=email)) is None])
        self.logger.debug(f"{self.api_name}: bulk download of {len(emails)} entries.")
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
            if source is None:
                title = exposure['title']
                match = self.domain_matcher.match(title)
                if match:
                    source = match.group(0)
                else:
                    found = False
                    for title_part, title_value in self.title_mapper.items():
                        if title_part.lower() in title.lower():
                            found = True
                            source = title_value
                            break
                    if not found:
                        self.logger.debug(f"{self.api_name}: no source found for {exposure}.")
                        source = title
            result['breaches'].append(BreachData(
                source,
                exposure['date'] if exposure['date'] else exposure['dateAdded']
            ))

        # We only keep the latest of the leaks having the same name
        final_breaches = {}
        for breach in result['breaches']:
            breach_data = asdict(breach)
            if breach_data['source'] not in final_breaches:
                final_breaches[breach_data['source']] = breach_data
            else:
                other_data = final_breaches[breach_data['source']]
                if (breach_data['date'][:7] if breach_data['date'] is not None else '') > (other_data['date'][:7] if other_data['date'] is not None else ''):
                    final_breaches[breach_data['source']] = other_data

        yield True, {
            'breaches': [
                BreachData(
                    breach['source'],
                    breach['date']
                ) for breach in final_breaches.values()
            ]
        }
