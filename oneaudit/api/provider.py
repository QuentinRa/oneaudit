from fake_useragent import UserAgent
from oneaudit.api.utils.caching import get_cached_result, set_cached_result
from oneaudit.utils.logs import get_project_logger
from requests import request
from json import JSONDecodeError


class DefaultProvider:
    def __init__(self, api_name, request_args, api_keys, show_notice=True):
        self.api_name = api_name
        self.unique_identifier = f'{api_name}_'

        self.request_args = request_args
        if "headers" not in self.request_args:
            self.request_args["headers"] = {}
        self.request_args["headers"]['User-Agent'] = UserAgent().random

        self.api_key = api_keys.get(api_name, None)
        self.is_endpoint_enabled = self.api_key is not None
        self.is_endpoint_terminated = False

        self.logger = get_project_logger()

        self.rate_limit_status_codes = [429]

        if show_notice:
            self.show_notice()

    def show_notice(self, is_endpoint_enabled=None):
        is_endpoint_enabled = is_endpoint_enabled if is_endpoint_enabled else self.is_endpoint_enabled
        if not is_endpoint_enabled:
            self.logger.warning(f"API '{self.api_name}' is not enabled.")
        else:
            self.logger.info(f"API '{self.api_name}' was enabled.")

    def fetch_results_using_cache(self, variable_key, **kwargs):
        cached = True
        cached_result_key = self.unique_identifier + variable_key
        data = get_cached_result(self.api_name, cached_result_key)
        if data is None:
            cached = False
            data = self.fetch_result_without_cache(**kwargs)
            set_cached_result(self.api_name, cached_result_key, data)

        return cached, data

    def fetch_result_without_cache(self, **kwargs):
        response = self.handle_request(**kwargs)
        if not self.is_response_valid(response):
            return self.fetch_result_without_cache(**kwargs)
        try:
            return response.json()
        except JSONDecodeError:
            self.logger.error(f"Provider: {self.__class__.__name__}")
            self.logger.error(f"Request: {self.request_args}")
            self.logger.error(f"Response code: {response.status_code}")
            self.logger.error(response.text)
            raise Exception(f"Unexpected response. Could not parse JSON.")

    def is_response_valid(self, response):
        if response.status_code in self.rate_limit_status_codes:
            self.handle_rate_limit(response)
            return False

        if response.status_code == 401:
            raise Exception(f"[!] {self.__class__.__name__}: {response.text}")

        if response.status_code not in [200, 201, 204]:
            self.logger.error(f"Provider: {self.__class__.__name__}")
            self.logger.error(f"Response code: {response.status_code}")
            self.logger.error(response.text)
            raise Exception("This response code was not allowed/handled.")

        return True

    def handle_request(self, **kwargs):
        return request(**self.request_args)

    def handle_rate_limit(self, response):
        """
        Some APIs are returning information about the time
        to wait in their headers.
        """
        pass

    def get_rate(self):
        return 5