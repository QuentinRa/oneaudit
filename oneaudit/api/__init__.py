import argparse
import json
import os
import hashlib
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


def set_cached_result(key, data):
    url_hash = "../cache/" + hashlib.md5(key.encode('utf-8')).hexdigest() + ".cache"
    with open(url_hash, 'w') as f:
        json.dump({
            "timestamp": time.time(),
            "response": data
        }, f)


def get_cached_result(key):
    url_hash = "../cache/" + hashlib.md5(key.encode('utf-8')).hexdigest() + ".cache"
    if os.path.exists(url_hash):
        with open(url_hash, 'r') as f:
            cached_data = json.load(f)
            timestamp = cached_data['timestamp']
            if time.time() - timestamp < 7 * 24 * 60 * 60:
                return cached_data['response']
    return None