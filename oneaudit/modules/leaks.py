import argparse
import cmd
import json
import logging
import os
import re
import time
import unidecode
import oneaudit.api.leaks
import oneaudit.modules
import oneaudit.utils

email_formats = {
    'first.last': '{firstname}.{lastname}@{domain}',
    'first_last': '{firstname}_{lastname}@{domain}',
    'firstlast': '{firstname}{lastname}@{domain}',
    'last.first': '{lastname}{firstname}@{domain}',
    'f.last': '{firstname[0]}.{lastname}@{domain}',
    'flast': '{firstname[0]}{lastname}@{domain}',
}


class LeaksCleanProgramData:
    def __init__(self, args):
        oneaudit.utils.args_parse_parse_verbose(self, args)
        with open(args.input, 'r') as file_data:
            self.data = json.load(file_data)
        self.output_file = args.output
        self.should_resume_process = args.resume_flag


class LeaksDownloadProgramData:
    def __init__(self, args):
        oneaudit.utils.args_parse_parse_verbose(self, args)
        oneaudit.api.args_parse_api_config(self, args)
        with open(args.input, 'r') as file_data:
            self.data = json.load(file_data)
        self.output_file = args.output
        self.company_domain = args.company_domain


class LeaksOSINTParseProgramData:
    def __init__(self, args):
        oneaudit.utils.args_parse_parse_verbose(self, args)
        self.data = {
            'entries': []
        }
        for file in args.input:
            with open(file, 'r') as file_data:
                self.data['entries'].extend(json.load(file_data)["entries"])
        self.output_file = args.output
        self.domain = args.company_domain
        self.domain_aliases = [self.domain] + args.domain_aliases
        self.email_format = email_formats[args.email_format]
        self.email_regex = re.compile(r'\b[A-Za-z0-9.-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')


class LeaksCredentialProcessor(cmd.Cmd):
    intro = "Welcome to the leaks credential processor. Type 'help' for a list of commands."
    prompt = "(leak) "

    def __init__(self, args: LeaksCleanProgramData):
        super().__init__()
        self.credentials = args.data.get('credentials', [])
        self.index = -1
        self.output_file = args.output_file
        self.new_credentials = {}
        if os.path.exists(self.output_file):
            if args.should_resume_process:
                    try:
                        with open(self.output_file, 'r') as file_data:
                            data = json.load(file_data)
                            for entry in data['credentials']:
                                self.new_credentials[entry['login']] = entry['passwords']
                            self.index = int(data.get("index", 0))
                    except json.JSONDecodeError:
                        pass
            else:
                self.output_file += "." + str(time.time())

    def do_next(self, arg):
        if self.index < len(self.credentials):
            self.index += 1
            credential = self.credentials[self.index]
            print(f"Processing {credential['login']}")
            for i, password in enumerate(credential['passwords'], start=1):
                print(f"{i}. {password}")
            print()
        else:
            print("No more credentials to skip.")

    def do_exit(self, arg):
        credentials = [
            {
                "login": email,
                "passwords": passwords
            }
            for email, passwords in self.new_credentials.items()
        ]

        with open(self.output_file, 'w') as output_file:
            json.dump({
                "version": 1.0,
                "index": self.index,
                "credentials": credentials
            }, output_file, indent=4)

        return True

    def _keep_password(self, index):
        if 0 <= self.index < len(self.credentials):
            credential = self.credentials[self.index]
            index = index - 1
            if index < len(credential['passwords']):
                key = credential['login']
                if key not in self.new_credentials:
                    self.new_credentials[key] = []
                self.new_credentials[key].append(credential['passwords'][index])
                print("Kept:", self.new_credentials[key])
                return

        print("Invalid index")

    def default(self, line):
        aliases = {
            'n': 'next',
            's': 'next',
            'q': 'exit',
            'quit': 'exit',
        }

        command = aliases.get(line.lower())
        if command:
            return self.onecmd(command)
        elif line.isnumeric():
            return self._keep_password(int(line))
        else:
            print(f"Unknown command or alias: {line}")


def parse_args(parser: argparse.ArgumentParser, module_parser: argparse.ArgumentParser):
    global email_formats

    submodule_parser = module_parser.add_subparsers(dest='action', required=True)

    parse_osint = submodule_parser.add_parser('parse', help='Parse OSINT results into records suitable for the "download" module.')
    parse_osint.add_argument('-i', metavar='input.json', dest='input', help='JSON contacts file from OSINT investigations.', action='append', required=True)
    parse_osint.add_argument('-o', metavar='output.json', dest='output', help='Export results as JSON.', required=True)
    parse_osint.add_argument('-d', '--domain', dest='company_domain', help='For example, "example.com".', required=True)
    parse_osint.add_argument('-f', '--format', dest='email_format', help='Format used to generate company emails.', choices=email_formats.keys(), required=True)
    parse_osint.add_argument('--alias', dest='domain_aliases', default=[], action='append', help='Alternative domain names that should be investigated.')
    oneaudit.utils.args_verbose_config(parse_osint)

    clean_leaks = submodule_parser.add_parser('clean', help='Select which passwords to keep.')
    clean_leaks.add_argument('-i', metavar='input.json', dest='input', help='JSON file with leaked credentials.', required=True)
    clean_leaks.add_argument('-o', metavar='output.json', dest='output', help='Export results as JSON.', required=True)
    clean_leaks.add_argument('-r', action='store_true', dest='resume_flag', help='Start working for the previous output file.')
    oneaudit.utils.args_verbose_config(clean_leaks)

    download_leaks = submodule_parser.add_parser('download', description='Download leaks from enabled APIs.')
    download_leaks.add_argument('-i', metavar='input.json', dest='input', help='JSON file with known data about targets.', required=True)
    download_leaks.add_argument('-d', '--domain', dest='company_domain', help='For example, "example.com".')
    download_leaks.add_argument('-o', metavar='output.json', dest='output', help='Export results as JSON.', required=True)
    oneaudit.api.args_api_config(download_leaks)
    oneaudit.utils.args_verbose_config(download_leaks)

    return parser.parse_args()


def run(parser, module_parser):
    args = parse_args(parser, module_parser)
    logger = logging.getLogger("oneaudit")
    if args.action == 'clean':
        processor = LeaksCredentialProcessor(LeaksCleanProgramData(args))
        processor.cmdloop()
        return
    elif args.action == 'download':
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
    elif args.action == 'parse':
        args = LeaksOSINTParseProgramData(args)
        result = {
            'version': 1.1,
            'credentials': []
        }
        found = {}
        for entry in args.data['entries']:
            for target in entry['targets']:
                firstname = target['first_name'] if 'first_name' in target else ""
                lastname = target['last_name'] if 'last_name' in target else ""
                if 'full_name' in target and ' ' in target['full_name']:
                    words = target['full_name'].split()
                    firstname = words[0]
                    lastname = ''.join(words[1:])

                email = args.email_format.format(firstname=firstname, lastname=lastname, domain=args.domain)
                email = unidecode.unidecode(email.lower().replace(" ", ""))

                email_valid = firstname and lastname and "." not in firstname+lastname
                email_valid = email_valid and "_" not in firstname+lastname
                email_valid = email_valid and args.email_regex.match(email) is not None
                if not email_valid:
                    if email not in found:
                        logger.warning(f"Invalid Computed Login: {email}")
                        found[email] = {}
                    continue

                verified = False
                emails = {email}
                for target_email_data in target["emails"] if "emails" in target else []:
                    target_email = target_email_data['email']
                    is_target_email_verified = target_email_data['verified']
                    verified = verified or (email == target_email and is_target_email_verified)
                    allowed = [domain for domain in args.domain_aliases if target_email.endswith(domain)] == []
                    if allowed:
                        emails.add(target_email.lower())
                for target_domain in args.domain_aliases:
                    if target_domain == args.domain:
                        continue
                    emails.add(email.replace(args.domain, target_domain))
                emails = list(emails)
                logger.info(f"Using login: '{email}' and the following emails: {emails}")

                if email not in found:
                    found[email] = {
                        "login": email,
                        "verified": verified,
                        "emails": emails
                    }
                else:
                    found[email]["verified"] = verified or found[email]["verified"]
                    found[email]["emails"].extend(emails)

        result["credentials"] = [{
            "login": c["login"],
            "verified": c["verified"],
            "emails": list(set(c["emails"]))
        } for c in found.values() if "login" in c]

    with open(args.output_file, 'w') as output_file:
        json.dump(result, output_file, cls=oneaudit.modules.GenericObjectEncoder,  indent=4)
