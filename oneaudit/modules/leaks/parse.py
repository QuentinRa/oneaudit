from oneaudit.api.leaks import LeakTarget
from oneaudit.utils.io import save_to_json
from oneaudit.utils.logs import args_verbose_config, args_parse_parse_verbose, get_project_logger
from unidecode import unidecode
from json import JSONDecodeError
import json
import re

email_formats = {
    'first': '{firstname}@{domain}',
    'last': '{firstname}@{domain}',

    'firstlast': '{firstname}{lastname}@{domain}',
    'lastfirst': '{lastname}{firstname}@{domain}',

    'first.last': '{firstname}.{lastname}@{domain}',
    'last.first': '{lastname}.{firstname}@{domain}',

    'first_last': '{firstname}_{lastname}@{domain}',
    'last_first': '{firstname}_{lastname}@{domain}',

    'f.last': '{firstname[0]}.{lastname}@{domain}',
    'flast': '{firstname[0]}{lastname}@{domain}',
    'fl': '{firstname[0]}{lastname[0]}@{domain}',
}


def define_args(parent_parser):
    parse_osint = parent_parser.add_parser('parse', help='Parse OSINT results into records suitable for the "download" module.')
    parse_osint.add_argument('-i', metavar='input.json', dest='input_files', help='JSON contacts file from OSINT investigations.', action='append', required=True)
    parse_osint.add_argument('-o', metavar='output.json', dest='output_file', help='Export results as JSON.', required=True)
    parse_osint.add_argument('-d', '--domain', dest='domain', help='For example, "example.com".', required=True)
    parse_osint.add_argument('-f', '--format', dest='email_format', help='Format used to generate company emails.', choices=email_formats.keys(), required=True)
    parse_osint.add_argument('--alias', dest='domain_aliases', default=[], action='append', help='Alternative domain names that should be investigated.')
    args_verbose_config(parse_osint)


def run(args):
    args_parse_parse_verbose(args)
    args.domain_aliases = [args.domain] + args.domain_aliases
    email_regex = re.compile(r'\b[A-Za-z0-9.-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
    targets, found = [], {}
    verified_count = {}
    logger = get_project_logger()

    # Read all entries
    for file in args.input_files:
        try:
            with open(file, 'r') as file_data:
                entries = json.load(file_data)['entries']
                targets.extend(entries)
        except JSONDecodeError as e:
            raise Exception(f"Error when reading 'targets' in {file}: {e}")

    # For statistics
    for email_format_id in email_formats.keys():
        verified_count[email_format_id] = set()

    # Parse them
    logger.info(f"Parsing {len(targets)} entries.")
    for target in targets:
        # PART 1 - Compute login email
        firstname = target['first_name'] if 'first_name' in target else ""
        lastname = target['last_name'] if 'last_name' in target else ""
        if 'full_name' in target and ' ' in target['full_name']:
            words = target['full_name'].split()
            firstname = words[0]
            lastname = ''.join(words[1:])
        if 'emails' not in target:
            target['emails'] = []
        if 'birth_year' not in target:
            target['birth_year'] = None

        # Generate email using all formats
        candidates = {}
        for email_format_id, email_format in email_formats.items():
            computed_email = email_format.format(firstname=firstname, lastname=lastname, domain=args.domain) if firstname.strip() and lastname.strip() else ""
            computed_email = unidecode(computed_email.lower().replace(" ", "").replace("/", "").replace("'", "").strip())
            candidates[email_format_id] = computed_email

        computed_email = candidates[args.email_format]
        email_f, email_l = unidecode(firstname).strip(), unidecode(lastname).strip()
        email_valid = email_f and email_l and "." not in email_f+email_l
        email_valid = email_valid and "_" not in email_f+email_l
        email_valid = email_valid and email_regex.match(computed_email) is not None
        if not email_valid:
            if computed_email not in found:
                logger.warning(f"Invalid Computed Login: {computed_email} (verified={[t['email'] for t in target["emails"] if t['verified']]})")
                found[computed_email] = {}
            continue

        # PART 2 - Only keep one email from the target domain
        #    And identify whether the login is verified or not
        verified = False
        emails = {computed_email}
        for target_email_data in target["emails"]:
            target_email = target_email_data['email']
            is_target_email_verified = target_email_data['verified']
            verified = verified or (computed_email == target_email and is_target_email_verified)
            allowed = [domain for domain in args.domain_aliases if target_email.endswith(domain)] == []
            if allowed:
                emails.add(target_email.lower())
            elif is_target_email_verified:
                # Always add verified emails, regardless of any rule
                emails.add(target_email.lower())
                # Compute stats
                email_format_id = [email_format_id for email_format_id, candidate in candidates.items() if candidate == target_email]
                if email_format_id:
                    verified_count[email_format_id[0]].add(target_email)

        for target_domain in args.domain_aliases:
            if target_domain == args.domain:
                continue
            emails.add(computed_email.replace(args.domain, target_domain))

        emails = list(emails)
        logger.debug(f"Using login: '{computed_email}' and the following emails: {emails}")

        if computed_email not in found:
            found[computed_email] = {
                "login": computed_email,
                "verified": verified,
                "emails": emails,
                "links": target['links'],
                "birth_year": target['birth_year']
            }
        else:
            found[computed_email]["verified"] = verified or found[computed_email]["verified"]
            found[computed_email]["birth_year"] = target['birth_year'] if target['birth_year'] else found[computed_email]["birth_year"]
            found[computed_email]["emails"].extend(emails)
            for k, v in target['links'].items():
                if k in found[computed_email]['links']:
                    continue
                found[computed_email]['links'][k] = v

    logger.info(f"Found the following verified logins.")
    for email_format_id, verified_count_per_format in verified_count.items():
        logger.info(f"     Format: {email_format_id:20} -> Result: {len(verified_count_per_format):5}")

    save_to_json(args.output_file, {
        'version': 1.2,
        'credentials': [
            LeakTarget(
                c["login"],
                c["verified"],
                list(set(c["emails"])),
                {
                    "links": c["links"],
                    "birth_year": c["birth_year"],
                }
            ) for c in found.values() if "login" in c
        ]
    })
