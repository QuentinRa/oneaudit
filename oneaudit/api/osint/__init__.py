import logging
import time
import dataclasses
import oneaudit.api

class OSINTProviderManager(oneaudit.api.DefaultProviderManager):
    def __init__(self, api_keys, cache_only=False):
        import oneaudit.api.osint.rocketreach
        super().__init__([
            oneaudit.api.osint.rocketreach.RocketReachAPI(api_keys, cache_only)
        ])

    def parse_records(self, file_source, employee_filter, input_file):
        result = []

        for provider in self.providers:
            try:
                result.append({
                    "source": provider.api_name,
                    "date": time.time(),
                    "version": 1.0,
                    "targets": provider.parse_records_from_file(file_source, employee_filter, input_file)
                })
            except Exception as e:
                logging.error(f"Error during parsing of {input_file} by {provider.api_name}: {e}")

        return result

    def fetch_records(self, company_name):
        result = {}
        for provider in self.providers:
            result[provider.api_name] = []
        result = self._call_method_on_each_provider(result, 'fetch_targets_for_company', company_name)
        final_result = []
        for provider in self.providers:
            final_result.append(
                {
                    "source": provider.api_name,
                    "date": time.time(),
                    "version": provider.api_version,
                    "targets": result[provider.api_name]
                }
            )

        return final_result


class OSINTProvider(oneaudit.api.DefaultProvider):
    def __init__(self, request_args, api_name, api_keys, api_version=1.0, show_notice=True):
        super().__init__(api_name, request_args, api_keys, show_notice)
        self.api_version = api_version

    def parse_records_from_file(self, file_source, employee_filter, input_file):
        return []

    def fetch_targets_for_company(self, company_name):
        return []


@dataclasses.dataclass(frozen=True, order=True)
class OSINTScrappedDataFormat:
    full_name: str
    linkedin_url: str
    birth_year: str
    count: int

    def to_dict(self):
        return {
            "full_name": self.full_name,
            "linkedin_url": self.linkedin_url,
            "birth_year": self.birth_year,
            "count": self.count,
        }