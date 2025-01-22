from oneaudit.api.leaks import LeakTarget
from oneaudit.api.utils.caching import args_api_config, args_parse_api_config
from oneaudit.api.leaks.manager import OneAuditLeaksAPIManager
from oneaudit.modules.leaks.clean import clean_credentials
from oneaudit.utils.io import save_to_json, to_json_string, serialize_api_object
from oneaudit.utils.logs import args_verbose_config, args_parse_parse_verbose
from json import load as json_load, loads as json_loads


def define_args(parent_parser):
    download_parser = parent_parser.add_parser('download', description='Download leaks from enabled APIs.')
    input_group = download_parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument('-i', '--input', metavar='input.json', dest='input_file', help='JSON file with known data about targets.')
    input_group.add_argument('-e', metavar='john@example.com', dest='input_email', help='Process only the given email (unless -d is specified).')
    #input_group.add_argument('-w', metavar='wordlist.txt', dest='input_email', help='Test only one email.')

    download_parser.add_argument('-d', '--domain', dest='company_domain', help='For example, "example.com".')
    download_parser.add_argument('-o', '--output', metavar='output.json', dest='output_file', help='Export results as JSON.')
    download_parser.add_argument('-r', action='store_true', dest='can_use_cache_even_if_disabled', help='Reuse cached result even for disabled APIs.')
    download_parser.add_argument('-c', '--clean', action='store_true', dest='run_clean', help='Run the "leaks clean" submodule on the output.')
    args_api_config(download_parser)
    args_verbose_config(download_parser)
    return download_parser


def run(args):
    if args.input_file and not args.output_file:
        raise args.download_parser.error("You must use -o/--output when using -i/--input.")
    args_parse_parse_verbose(args)
    api_keys = args_parse_api_config(args)
    return compute_result(args, api_keys)

def compute_result(args, api_keys):
    # Load Credentials
    if args.input_file:
        with open(args.input_file, 'r') as file_data:
            credentials = json_load(file_data)['credentials']
    else:
        credentials = [serialize_api_object(LeakTarget(args.input_email, False, False, [args.input_email], {}))]

    # Inspect them
    provider = OneAuditLeaksAPIManager(api_keys, args.can_use_cache_even_if_disabled)
    domain_data = provider.investigate_domain(args.company_domain)
    credentials = provider.investigate_leaks(credentials, domain_data['emails'])
    del domain_data['emails']

    result = {
        'version': 1.7,
        'credentials': credentials if not args.run_clean else clean_credentials(json_loads(to_json_string(credentials))),
        "additional": domain_data,
    }
    if args.output_file:
        save_to_json(args.output_file, result)
    else:
        print(to_json_string(result))
    return result
