from oneaudit.api.leaks.provider import OneAuditLeaksAPIProvider, BreachDataFormat
from datetime import datetime
from dateutil.relativedelta import relativedelta


# https://spycloud.com/
class SpyCloudAPI(OneAuditLeaksAPIProvider):
    def __init__(self, api_keys):
        super().__init__(
            api_name='spycloud',
            request_args={
                'method': 'GET',
            },
            api_keys=api_keys
        )
        self.api_endpoint = 'https://portal.spycloud.com/endpoint/enriched-stats/{email}'

    def fetch_email_results(self, email):
        # Update parameters
        self.request_args['url'] = self.api_endpoint.format(email=email)
        # Send the request
        cached, data = self.fetch_results_using_cache(f"public_{email}")
        records, last, last_period = data['you']["records"], data['you']["discovered"], data['you']["discovered_unit"]
        result = {
            'breaches': [
                BreachDataFormat(f"SpyCloud [{records}]", self.compute_date(last, last_period).strftime('%Y-%m'))
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


    def handle_rate_limit(self, response):
        self.is_endpoint_enabled = False

    def get_request_rate(self):
        return 2