import logging
import time
import oneaudit.api

class OSINTProviderManager(oneaudit.api.DefaultProviderManager):
    def __init__(self, api_keys):
        import oneaudit.api.osint.rocketreach
        super().__init__([
            oneaudit.api.osint.rocketreach.RocketReachAPI(api_keys)
        ])

    def parse_records(self, file_source, input_file):
        result = []

        for provider in self.providers:
            try:
                result.append({
                    "source": provider.api_name,
                    "date": time.time(),
                    "version": 1.0,
                    "targets": provider.parse_records_from_file(file_source, input_file)
                })
            except Exception as e:
                logging.error(f"Error during parsing of {input_file} by {provider.api_name}: {e}")

        return result

    def fetch_records(self, company_name):
        result = {}
        for provider in self.providers:
            result[provider.api_name] = []
        result = self._call_method_on_each_provider(result, 'fetch_targets_for_company', company_name)
        print(result)
        # {
        #             "source": self.api_name,
        #             "date": time.time(),
        #             "version": self.api_version,
        #             "targets": self._fetch_targets_for_company(company_name)
        #         }


class OSINTProvider(oneaudit.api.DefaultProvider):
    def __init__(self, unique_identifier, request_args, api_name, api_keys, api_version=1.0):
        super().__init__(unique_identifier, request_args, api_name, api_keys)
        self.api_version = api_version

    def parse_records_from_file(self, file_source, input_file):
        return []

    def fetch_targets_for_company(self, company_name):
        return []
