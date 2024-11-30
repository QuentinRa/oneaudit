from oneaudit.api.leaks import LeaksAPICapability, BreachData
from oneaudit.api.leaks.provider import OneAuditLeaksAPIProvider
from datetime import datetime
from dateutil.relativedelta import relativedelta
from time import sleep


# https://spycloud.com/
class SpyCloudAPI(OneAuditLeaksAPIProvider):
    def _init_capabilities(self, api_key, api_keys):
        return [LeaksAPICapability.INVESTIGATE_LEAKS_BY_EMAIL] if api_key is not None else []

    def handle_rate_limit(self, response):
        sleep(30)

    def get_request_rate(self):
        return 2

    def __init__(self, api_keys):
        super().__init__(
            api_name='spycloud',
            request_args={
                'method': 'GET',
            },
            api_keys=api_keys
        )
        self.api_endpoint = 'https://portal.spycloud.com/endpoint/enriched-stats/{email}'

    def investigate_leaks_by_email(self, email):
        # Update parameters
        self.request_args['url'] = self.api_endpoint.format(email=email)
        # Send the request
        cached, data = self.fetch_results_using_cache(f"public_{email}", default={
            'you': { 'records': 0, 'discovered': None, 'discovered_unit': None }
        })
        records, last, last_period = data['you']["records"], data['you']["discovered"], data['you']["discovered_unit"]
        result = {
            'breaches': [
                BreachData(f"SpyCloud [{records}]", self.compute_date(last, last_period).strftime('%Y-%m'))
            ]
        } if records != 0 else {}

        yield cached, result

    def compute_date(self, last, last_period):
        current_date = datetime.now()
        if last_period.lower() in "days":
            return current_date - relativedelta(days=last)
        elif last_period.lower() in "weeks":
            return current_date - relativedelta(weeks=last)
        elif last_period.lower() in "months":
            return current_date - relativedelta(months=last)
        elif last_period.lower() in "years":
            return current_date - relativedelta(years=last)
        else:
            raise ValueError(f"Unsupported unit: {last_period}")
