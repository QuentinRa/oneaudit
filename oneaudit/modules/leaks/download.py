class LeaksDownloadProgramData:
    def __init__(self, args):
        oneaudit.utils.args_parse_parse_verbose(self, args)
        oneaudit.api.args_parse_api_config(self, args)
        with open(args.input, 'r') as file_data:
            self.data = json.load(file_data)
        self.output_file = args.output
        self.company_domain = args.company_domain


def xxx():
    download_leaks = submodule_parser.add_parser('download', description='Download leaks from enabled APIs.')
    download_leaks.add_argument('-i', metavar='input.json', dest='input', help='JSON file with known data about targets.', required=True)
    download_leaks.add_argument('-d', '--domain', dest='company_domain', help='For example, "example.com".')
    download_leaks.add_argument('-o', metavar='output.json', dest='output', help='Export results as JSON.', required=True)
    oneaudit.api.args_api_config(download_leaks)
    oneaudit.utils.args_verbose_config(download_leaks)


def run(args):
    args = LeaksDownloadProgramData(args)
    provider = oneaudit.api.leaks.LeaksProviderManager(args.api_keys)
    results = {}
    provider.prepare_for_targets([email for cred in args.data['credentials'] for email in cred['emails']])
    additional_data = provider.investigate_domain(args.company_domain)
    provider.sort_results(additional_data, additional_data)

    for credential in args.data['credentials']:
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

    credentials = []
    for login, data in results.items():
        final_data = {'login': login}

        # Attempt to crack hashes
        data = provider.investigate_hashes(login, data)

        # Sort results
        provider.sort_results(data, final_data)

        # Add
        credentials.append(final_data)

    result = {
        'version': 1.3,
        'credentials': credentials,
        "additional": additional_data,
    }
    with open(args.output_file, 'w') as output_file:
        json.dump(result, output_file, cls=oneaudit.modules.GenericObjectEncoder,  indent=4)