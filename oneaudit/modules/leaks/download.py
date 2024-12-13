from oneaudit.api.utils.caching import args_api_config, args_parse_api_config
from oneaudit.api.leaks.manager import OneAuditLeaksAPIManager
from oneaudit.utils.io import save_to_json
from oneaudit.utils.logs import args_verbose_config, args_parse_parse_verbose
import json


def define_args(parent_parser):
    download_leaks = parent_parser.add_parser('download', description='Download leaks from enabled APIs.')
    download_leaks.add_argument('-i', metavar='input.json', dest='input_file', help='JSON file with known data about targets.', required=True)
    download_leaks.add_argument('-d', '--domain', dest='company_domain', help='For example, "example.com".')
    download_leaks.add_argument('-o', metavar='output.json', dest='output_file', help='Export results as JSON.', required=True)
    download_leaks.add_argument('-r', action='store_true', dest='can_use_cache_even_if_disabled', help='Reuse cached result even for disabled APIs.')
    args_api_config(download_leaks)
    args_verbose_config(download_leaks)


def run(args):
    args_parse_parse_verbose(args)
    api_keys = args_parse_api_config(args)

    # Load Credentials
    with open(args.input_file, 'r') as file_data:
        credentials = json.load(file_data)['credentials']

    # Inspect them
    provider = OneAuditLeaksAPIManager(api_keys, args.can_use_cache_even_if_disabled)
    domain_data = provider.investigate_domain(args.company_domain)
    credentials = provider.investigate_leaks(credentials, domain_data['emails'])
    del domain_data['emails']

    save_to_json(args.output_file, {
        'version': 1.7,
        'credentials': credentials,
        "additional": domain_data,
    })
