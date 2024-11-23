import argparse
import logging
import fake_useragent
import requests
import hashlib
import json
import os
import time


def args_api_config(parser: argparse.ArgumentParser):
    parser.add_argument('--config', metavar='config.json', dest='api_config', help='Path to the config.json file with API settings.')


def args_parse_api_config(obj, args):
    config_file = args.api_config if args.api_config else 'config.json'
    obj.api_keys = {}
    if os.path.exists(config_file):
        try:
            with open(config_file, 'r') as config_file:
                keys = json.load(config_file)
                for api, key in keys.items():
                    obj.api_keys[api] = key
        except json.JSONDecodeError:
            pass


def set_cached_result(api_name, key, data):
    url_hash = f"../cache/{api_name}/" + hashlib.md5(key.encode('utf-8')).hexdigest() + ".cache"
    with open(url_hash, 'w') as f:
        json.dump({
            "timestamp": time.time(),
            "response": data
        }, f)


def get_cached_result(api_name, key):
    url_hash = f"../cache/{api_name}/" + hashlib.md5(key.encode('utf-8')).hexdigest() + ".cache"
    url_hash_directory = os.path.dirname(url_hash)
    if not os.path.exists(url_hash_directory):
        os.mkdir(url_hash_directory)
    if os.path.exists(url_hash):
        with open(url_hash, 'r') as f:
            cached_data = json.load(f)
            timestamp = cached_data['timestamp']
            if time.time() - timestamp < 7 * 24 * 60 * 60:
                return cached_data['response']
    return None


class DefaultProviderManager:
    def __init__(self, providers):
        self.last_called = {}
        self.providers = providers

    def trigger(self, handler, wait_time):
        now = time.time()
        last_called = self.last_called.get(handler, now)
        time_waited = now - last_called

        #print(f"Current time is {now}")
        #print(f"Last call to {handler} was at {last_called}: {time_waited}")

        if time_waited < wait_time:
            time_to_wait = wait_time - time_waited
            print(f"We need to wait {time_to_wait}")
            time.sleep(time_to_wait)

        self.last_called[handler] = time.time()

    def _call_method_on_each_provider(self, result, method_name, *args):
        for provider in self.providers:
            if not provider.is_endpoint_enabled:
                continue
            provider.logger.info(f"Querying leaks on {provider.api_name} (args={args})")
            for cached, api_result in getattr(provider, method_name, None)(*args):
                if not cached:
                    self.trigger(provider.__class__.__name__, provider.get_rate())
                for k, v in api_result.items():
                    result[k].extend(v)

        for k, v in result.items():
            result[k] = sorted([e for e in set(v) if e])

        return result

class DefaultProvider:
    def __init__(self, unique_identifier, request_args, api_name, api_keys):
        self.api_name = api_name
        self.unique_identifier = f'{api_name}_'

        self.request_args = request_args
        if "headers" not in self.request_args:
            self.request_args["headers"] = {}
        self.request_args["headers"]['User-Agent'] = fake_useragent.UserAgent().random

        self.api_key = api_keys.get(api_name, None)
        self.is_endpoint_enabled = self.api_key is not None

        self.logger = logging.getLogger('oneaudit')

    def fetch_results_using_cache(self, variable_key):
        cached = True
        cached_result_key = self.unique_identifier + variable_key
        data = get_cached_result(self.api_name, cached_result_key)
        if data is None:
            cached = False
            response = self.handle_request()
            if response.status_code == 429:
                self.handle_rate_limit(response)
                return self.fetch_results_using_cache(variable_key)

            if response.status_code == 401:
                self.logger.error(f"[!] {self.__class__.__name__}: {response.text}")
                return True, {}

            if response.status_code not in [200, 204]:
                self.logger.error(self.__class__.__name__)
                self.logger.error(response.text)
                self.logger.error(response.status_code)
                raise Exception("This response code was not allowed/handled.")

            data = response.json()

            set_cached_result(self.api_name, cached_result_key, data)

        return cached, data

    def handle_request(self):
        return requests.request(**self.request_args)

    def handle_rate_limit(self, response):
        """
        Some APIs are returning information about the time
        to wait in their headers.
        """
        pass

    def get_rate(self):
        return 5