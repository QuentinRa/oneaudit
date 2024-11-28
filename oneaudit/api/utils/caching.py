from oneaudit.utils.io import to_absolute_path
from oneaudit.utils.logs import get_project_logger
import argparse
import hashlib
import json
import os
import time

cache_folder = ".cache"


def args_api_config(parser: argparse.ArgumentParser):
    parser.add_argument('--config', metavar='config.json', dest='api_config', help='Path to the config.json file with API settings.')
    parser.add_argument('--cache', metavar='.cache', dest='cache_folder', help='Path to the cache folder used to cache requests.')


def args_parse_api_config(args):
    config_file = to_absolute_path(args.api_config if args.api_config else 'config.json')
    api_keys = {}
    logger = get_project_logger()
    if os.path.exists(config_file):
        logger.info(f"Found config file at '{config_file}'.")
        try:
            with open(config_file, 'r') as config_file:
                config_file = config_file.read()
                if "//" in config_file:
                    raise json.JSONDecodeError("JSON file cannot contain comments", "", 0)
                keys = json.loads(config_file)
                for api, key in keys.items():
                    api_keys[api] = key
        except json.JSONDecodeError as e:
            logger.error("Error while parsing config file")
            raise e
    else:
        logger.warning(f"No config file at '{config_file}'.")

    global cache_folder
    cache_folder = to_absolute_path(args.cache_folder if args.cache_folder else cache_folder)
    logger.info(f"Caching requests in '{cache_folder}'.")

    return api_keys


def set_cached_result(api_name, key, data):
    global cache_folder
    url_hash = f"{cache_folder}/{api_name}/" + hashlib.md5(key.encode('utf-8')).hexdigest() + ".cache"
    url_hash_directory = os.path.dirname(url_hash)
    if not os.path.exists(url_hash_directory):
        os.makedirs(url_hash_directory, exist_ok=True)
    if data is None:
        raise ValueError(f"Trying to save null data '{data}' for '{key}'")
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
        os.makedirs(url_hash_directory, exist_ok=True)
    if os.path.exists(url_hash):
        with open(url_hash, 'r') as f:
            cached_data = json.load(f)
            timestamp = cached_data['timestamp']
            if cached_data['response'] and (do_not_expire or time.time() - timestamp < 30 * 24 * 60 * 60):
                return cached_data['response']
    return None