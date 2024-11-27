from oneaudit.utils.io import save_to_json
from oneaudit.utils.logs import args_verbose_config, args_parse_parse_verbose, get_project_logger
from unidecode import unidecode
import json
import re

email_formats = {
    'first.last': '{firstname}.{lastname}@{domain}',
    'first_last': '{firstname}_{lastname}@{domain}',
    'firstlast': '{firstname}{lastname}@{domain}',
    'last.first': '{lastname}{firstname}@{domain}',
    'f.last': '{firstname[0]}.{lastname}@{domain}',
    'flast': '{firstname[0]}{lastname}@{domain}',
}

class LeaksOSINTParseProgramData:
    def __init__(self, args):
        args_parse_parse_verbose(self, args)
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


def define_args(parent_parser):
    parse_osint = parent_parser.add_parser('parse', help='Parse OSINT results into records suitable for the "download" module.')
    parse_osint.add_argument('-i', metavar='input.json', dest='input', help='JSON contacts file from OSINT investigations.', action='append', required=True)
    parse_osint.add_argument('-o', metavar='output.json', dest='output', help='Export results as JSON.', required=True)
    parse_osint.add_argument('-d', '--domain', dest='company_domain', help='For example, "example.com".', required=True)
    parse_osint.add_argument('-f', '--format', dest='email_format', help='Format used to generate company emails.', choices=email_formats.keys(), required=True)
    parse_osint.add_argument('--alias', dest='domain_aliases', default=[], action='append', help='Alternative domain names that should be investigated.')
    args_verbose_config(parse_osint)


def run(args):
    print(args)
    return
    args = LeaksOSINTParseProgramData(args)
    logger = get_project_logger()
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
            email = unidecode(email.lower().replace(" ", "").replace("/", "").strip())

            email_f, email_l = unidecode(firstname).strip(), unidecode(lastname).strip()
            email_valid = email_f and email_l and "." not in email_f+email_l
            email_valid = email_valid and "_" not in email_f+email_l
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

    save_to_json(args.output_file, result)
