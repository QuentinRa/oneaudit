from oneaudit.api import args_api_config, args_parse_api_config
from oneaudit.api.leaks import LeaksProviderManager
from oneaudit.utils.io import save_to_json
from oneaudit.utils.logs import args_verbose_config, args_parse_parse_verbose, get_project_logger
import json


def define_args(parent_parser):
    download_leaks = parent_parser.add_parser('download', description='Download leaks from enabled APIs.')
    download_leaks.add_argument('-i', metavar='input.json', dest='input_file', help='JSON file with known data about targets.', required=True)
    download_leaks.add_argument('-d', '--domain', dest='company_domain', help='For example, "example.com".')
    download_leaks.add_argument('-o', metavar='output.json', dest='output_file', help='Export results as JSON.', required=True)
    args_api_config(download_leaks)
    args_verbose_config(download_leaks)


def run(args):
    args_parse_parse_verbose(args)
    api_keys = args_parse_api_config(args)
    results = {}
    logger = get_project_logger()
    with open(args.input_file, 'r') as file_data:
        credentials = json.load(file_data)['credentials']

    provider = LeaksProviderManager(api_keys)
    provider.prepare_for_targets([email for cred in credentials for email in cred['emails']])
    additional_data = provider.investigate_domain(args.company_domain)
    provider.sort_results(additional_data, additional_data)

    try:
        for credential in credentials:
            key = credential['login']
            if key in results:
                continue
            results[key] = provider.get_base_data()
            for email in credential['emails']:
                was_modified, results[key] = provider.append_data(email, results[key])
                if was_modified and email == key:
                    credential['verified'] = True
                    logger.debug(f"Email {email} was verified due to leaks associated to it.")

            for login in results[key]["logins"]:
                if "@" not in login or ':' in login or login in credential['emails']:
                    continue
                raise Exception(f"Found new email that was not handled: {login}")

            results[key]['verified'] = credential['verified']
    except KeyboardInterrupt:
        logger.info("Stopping leak investigations.")

    credentials = []
    for login, data in results.items():
        final_data = {'login': login}
        # Attempt to crack hashes
        data = provider.investigate_hashes(login, data)
        # Sort results
        provider.sort_results(data, final_data)
        # Add
        credentials.append(final_data)

    save_to_json(args.output_file, {
        'version': 1.3,
        'credentials': credentials,
        "additional": additional_data,
    })
