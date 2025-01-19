from oneaudit.api import APIRateLimitException
from oneaudit.api.utils.caching import get_cached_result, set_cached_result
from oneaudit.utils.io import compute_checksum
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
        self.logger = _OneAuditCustomProviderLogger(get_project_logger(), self.api_name)

        # What can the endpoint do? Was it enabled ?
        self.capabilities = self._init_capabilities(self.api_key, api_keys)
        self.is_endpoint_enabled = len(self.capabilities) > 0
        self.only_use_cache = False

        # API status codes
        self.rate_limit_status_codes = [429]
        self.allowed_status_codes = [200, 201, 204]

        # Log the provider status
        if not self.is_endpoint_enabled:
            self.logger.debug("API is not enabled.")
        else:
            self.logger.info("API was enabled.")

    def get_request_rate(self):
        """Default is one request per five seconds"""
        return 5

    def _init_capabilities(self, api_key, api_keys):
        """
        Return a list of capabilities supported by this API.
        If none are returned, this API will be disabled.
        """
        raise NotImplementedError("API didn't define which capabilities were enabled.")

    def fetch_results_using_cache(self, key, default, **kwargs):
        cached = True
        cached_result_key = self.unique_identifier + key
        data = get_cached_result(self.api_name, cached_result_key, do_not_expire=self.only_use_cache, expiration_check=kwargs.get('expiration_check', 30 * 24 * 3600))
        if data is None:
            if self.only_use_cache:
                data = default
            else:
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
            self.logger.error(f'Response text: {response.text}')
            raise Exception(f"Unexpected response. Could not parse JSON.")

    def handle_request(self, **kwargs):
        try:
            return request(**self.request_args)
        except ReadTimeout:
            self.logger.error(f"API is unresponsive. It was disabled.")
            self.handle_api_shutdown()

    def is_response_valid(self, response):
        if response.status_code in self.rate_limit_status_codes:
            self.logger.warning(f"Hit rate-limit. Status code was: {response.status_code}.")
            self.handle_rate_limit(response)
            return False

        if response.status_code not in self.allowed_status_codes:
            self.logger.error(f"Provider: {self.__class__.__name__}")
            self.logger.error(f"Request: {self.request_args}")
            self.logger.error(f"Response code: {response.status_code}")
            self.logger.error(f'Response text: {response.text}')
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

    # Methods for bulk queries
    def _cache_indexed_data_if_required(self, key_format, indexed_data):
        key_formatter = f'{self.api_name}_{key_format}'
        for key, extracted_data in indexed_data.items():
            # Compute checksum
            cached_data = get_cached_result(self.api_name, key_formatter.format(key=key), True)
            cached_data_checksum = cached_data['checksum_sha256'] if cached_data and 'checksum_sha256' in cached_data else None
            extracted_data_checksum = compute_checksum(extracted_data)
            # Update database if data changed
            if extracted_data_checksum != cached_data_checksum:
                set_cached_result(self.api_name, key_formatter.format(key=key), {'checksum_sha256': extracted_data_checksum, **self._generate_cached_from_extracted(extracted_data)})

    def _generate_cached_from_extracted(self, extracted_data):
        return { "result": extracted_data }


class _OneAuditCustomProviderLogger:
    """
    One format to rule them all
    """
    def __init__(self, logger, prefix):
        self._logger = logger
        self.prefix = prefix

    def _prepend_prefix(self, message):
        return f"[{self.prefix}] - {message}"

    def debug(self, msg, *args, **kwargs):
        self._logger.debug(self._prepend_prefix(msg), *args, **kwargs)

    def info(self, msg, *args, **kwargs):
        self._logger.info(self._prepend_prefix(msg), *args, **kwargs)

    def warning(self, msg, *args, **kwargs):
        self._logger.warning(self._prepend_prefix(msg), *args, **kwargs)

    def error(self, msg, *args, **kwargs):
        self._logger.error(self._prepend_prefix(msg), *args, **kwargs)

    def exception(self, msg, *args, **kwargs):
        self._logger.exception(self._prepend_prefix(msg), *args, **kwargs)

    def critical(self, msg, *args, **kwargs):
        self._logger.critical(self._prepend_prefix(msg), *args, **kwargs)
