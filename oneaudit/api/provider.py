from oneaudit.api import APIRateLimitException
from oneaudit.api.utils.caching import get_cached_result, set_cached_result
from oneaudit.utils.logs import get_project_logger
from requests.exceptions import ReadTimeout
from fake_useragent import UserAgent
from requests import request
from json import JSONDecodeError


class OneAuditBaseProvider:
    """
    A provider (a.k.a. must be enabled, regardless of the API being FREE, PAID, or FREEMIUM)
    """
    def __init__(self, api_name, request_args, api_keys):
        # API Identifiers
        self.api_name = api_name
        self.api_key = api_keys.get(self.api_name)
        self.unique_identifier = f'{api_name}_'

        # Setting User-Agent
        self.request_args = request_args
        if "headers" not in self.request_args:
            self.request_args["headers"] = {}
        self.request_args["headers"]['User-Agent'] = UserAgent().random

        # Enable logs
        self.logger = get_project_logger()

        # What can the endpoint do? Was it enabled ?
        self.capabilities = self._init_capabilities(self.api_key, api_keys)
        self.is_endpoint_enabled = len(self.capabilities) > 0

        # API status codes
        self.rate_limit_status_codes = [429]
        self.allowed_status_codes = [200, 201, 204]

        # Log the provider status
        if not self.is_endpoint_enabled:
            self.logger.warning(f"API '{self.api_name}' is not enabled.")
        else:
            self.logger.info(f"API '{self.api_name}' was enabled.")

    def get_request_rate(self):
        """Default is one request per five seconds"""
        return 5

    def _init_capabilities(self, api_key, api_keys):
        """
        Return a list of capabilities supported by this API.
        If none are returned, this API will be disabled.
        """
        raise NotImplementedError("API didn't define which capabilities were enabled.")

    def fetch_results_using_cache(self, key, **kwargs):
        cached = True
        cached_result_key = self.unique_identifier + key
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

    def handle_request(self, **kwargs):
        try:
            return request(**self.request_args)
        except ReadTimeout:
            self.logger.error(f"API {self.api_name} is unresponsive. It was disabled.")
            self.handle_api_shutdown()

    def is_response_valid(self, response):
        if response.status_code in self.rate_limit_status_codes:
            self.handle_rate_limit(response)
            return False

        if response.status_code not in self.allowed_status_codes:
            self.logger.error(f"Provider: {self.__class__.__name__}")
            self.logger.error(f"Response code: {response.status_code}")
            self.logger.error(response.text)
            raise Exception("This response code was not allowed/handled.")

        return True

    def handle_rate_limit(self, response):
        """
        Some APIs are returning information about the time
        to wait in their headers. Some API may not have any credits,
        so they must be disabled here.
        """
        self.handle_api_shutdown()

    def handle_api_shutdown(self):
        """
        Some APIs are returning information about the time
        to wait in their headers. Some API may not have any credits,
        so they must be disabled here.
        """
        self.capabilities = []
        raise APIRateLimitException()
