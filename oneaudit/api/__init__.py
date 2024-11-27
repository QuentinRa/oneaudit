import argparse
import logging
import fake_useragent
import requests
import hashlib
import json
import os
import time

cache_folder = ".cache"


def args_api_config(parser: argparse.ArgumentParser):
    parser.add_argument('--config', metavar='config.json', dest='api_config', help='Path to the config.json file with API settings.')
    parser.add_argument('--cache', metavar='.cache', dest='cache_folder', help='Path to the cache folder used to cache requests.')


def args_parse_api_config(args):
    config_file = args.api_config if args.api_config else 'config.json'
    api_keys = {}
    if os.path.exists(config_file):
        try:
            with open(config_file, 'r') as config_file:
                keys = json.load(config_file)
                for api, key in keys.items():
                    api_keys[api] = key
        except json.JSONDecodeError:
            pass

    global cache_folder
    cache_folder = args.cache_folder if args.cache_folder else cache_folder

    return api_keys


def set_cached_result(api_name, key, data):
    global cache_folder
    url_hash = f"{cache_folder}/{api_name}/" + hashlib.md5(key.encode('utf-8')).hexdigest() + ".cache"
    url_hash_directory = os.path.dirname(url_hash)
    if not os.path.exists(url_hash_directory):
        os.mkdir(url_hash_directory)
    with open(url_hash, 'w') as f:
        json.dump({
            "timestamp": time.time(),
            "response": data
        }, f)


def get_cached_result(api_name, key, do_not_expire=False):
    global cache_folder
    url_hash = f"{cache_folder}/{api_name}/" + hashlib.md5(key.encode('utf-8')).hexdigest() + ".cache"
    url_hash_directory = os.path.dirname(url_hash)
    if not os.path.exists(url_hash_directory):
        os.mkdir(url_hash_directory)
    if os.path.exists(url_hash):
        with open(url_hash, 'r') as f:
            cached_data = json.load(f)
            timestamp = cached_data['timestamp']
            if do_not_expire or time.time() - timestamp < 30 * 24 * 60 * 60:
                return cached_data['response']
    return None


class DefaultProviderManager:
    def __init__(self, providers):
        self.last_called = {}
        self.providers = providers
        self.logger = logging.getLogger('oneaudit')

    def trigger(self, handler, wait_time):
        now = time.time()
        last_called = self.last_called.get(handler, now)
        time_waited = now - last_called

        self.logger.debug(f"Current time is {now}")
        self.logger.debug(f"Last call to {handler} was at {last_called}: {time_waited}")

        if time_waited < wait_time:
            time_to_wait = wait_time - time_waited
            self.logger.debug(f"We need to wait {time_to_wait}")
            time.sleep(time_to_wait)
        else:
            self.logger.debug(f"We don't need to wait.")

        self.last_called[handler] = time.time()

    def sort_results(self, source, output):
        for k, v in source.items():
            if isinstance(v, list):
                output[k] = sorted([e for e in set(v) if e])
            elif isinstance(v, bool):
                output[k] = v
            else:
                self.logger.error(f"Unexpected type for: k={k} v={v}")
                continue

    def _call_method_on_each_provider(self, result, method_name, *args):
        was_modified = False
        for provider in self.providers:
            if not provider.is_endpoint_enabled:
                continue
            provider.logger.info(f"Querying leaks on {provider.api_name} (args={args})")
            for cached, api_result in getattr(provider, method_name, None)(*args):
                if not cached:
                    self.trigger(provider.__class__.__name__, provider.get_rate())
                for k, v in api_result.items():
                    if not v:
                        continue
                    was_modified = True
                    if isinstance(v, list):
                        result[k].extend(v)
                    elif isinstance(v, bool):
                        result[k] = result[k] or v
                    else:
                        raise Exception(f"Unexpected type for {k}: {type(v)}")

        return was_modified, result

class DefaultProvider:
    def __init__(self, api_name, request_args, api_keys, show_notice=True):
        self.api_name = api_name
        self.unique_identifier = f'{api_name}_'

        self.request_args = request_args
        if "headers" not in self.request_args:
            self.request_args["headers"] = {}
        self.request_args["headers"]['User-Agent'] = fake_useragent.UserAgent().random

        self.api_key = api_keys.get(api_name, None)
        self.is_endpoint_enabled = self.api_key is not None
        self.is_endpoint_terminated = False

        self.logger = logging.getLogger('oneaudit')

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
        return response.json()

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
        return requests.request(**self.request_args)

    def handle_rate_limit(self, response):
        """
        Some APIs are returning information about the time
        to wait in their headers.
        """
        pass

    def get_rate(self):
        return 5

class FakeResponse:
    def __init__(self, status_code, response_data):
        self.status_code = status_code
        self._response_data = response_data

    def json(self):
        return self._response_data

class PaidAPIDisabledException(Exception):
    pass