from oneaudit.utils.io import to_absolute_path
from oneaudit.utils.logs import get_project_logger
import argparse
import hashlib
import json
import os
import time
import sqlite3

cache_folder = ".cache"
sqlite_connection = {}
sqlite_cursor = {}


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


def set_cached_result(api_name, key, data, from_timestamp=None):
    conn, cursor = create_cache_database(api_name)
    json_response = json.dumps(data)
    timestamp = int(time.time()) if not from_timestamp else from_timestamp
    if data is None:
        raise ValueError(f"Trying to save null data '{data}' for '{key}'")
    cursor.execute('''
        INSERT OR REPLACE INTO cache (response_key, json_response, timestamp)
        VALUES (?, ?, ?)
    ''', (key, json_response, timestamp))
    conn.commit()


def create_cache_database(api_name):
    global sqlite_connection, sqlite_cursor
    # Already opened
    if api_name in sqlite_connection:
        return sqlite_connection[api_name], sqlite_cursor[api_name]
    # Create/Load
    database_file = f"{cache_folder}/{api_name}.sqlite"
    database_folder = os.path.dirname(database_file)
    if not os.path.exists(database_folder):
        os.makedirs(database_folder, exist_ok=True)
    sqlite_connection[api_name] = sqlite3.connect(database_file)
    sqlite_cursor[api_name] = sqlite_connection[api_name].cursor()
    sqlite_cursor[api_name].execute('''
        CREATE TABLE IF NOT EXISTS cache (
            id INTEGER PRIMARY KEY,
            response_key TEXT UNIQUE,
            json_response TEXT,
            timestamp INTEGER
        )
    ''')
    sqlite_connection[api_name].commit()
    return sqlite_connection[api_name], sqlite_cursor[api_name]


def get_cached_result(api_name, key, do_not_expire=False):
    conn, cursor = create_cache_database(api_name)
    cursor.execute('SELECT json_response, timestamp FROM cache WHERE response_key = ?', (key,))
    row = cursor.fetchone()
    if row:
        json_response, timestamp = row
        current_time = int(time.time())
        if do_not_expire or current_time - timestamp < 30 * 24 * 60 * 60:
            return json.loads(json_response)
    else:
        # Backward capabilities
        url_hash = f"{cache_folder}/{api_name}/" + hashlib.md5(key.encode('utf-8')).hexdigest() + ".cache"
        url_hash_directory = os.path.dirname(url_hash)
        if not os.path.exists(url_hash_directory):
            return None

        if not os.path.exists(url_hash):
            return None

        with open(url_hash, 'r') as f:
            cached_data = json.load(f)
            timestamp = cached_data['timestamp']
            set_cached_result(api_name, key, cached_data['response'], timestamp)
        os.rename(url_hash, url_hash+".migrated")
        return get_cached_result(api_name, key, do_not_expire)
    return None
