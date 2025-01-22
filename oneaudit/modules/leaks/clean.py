from oneaudit.api.leaks import BreachData
from oneaudit.utils.logs import args_verbose_config, args_parse_parse_verbose, get_project_logger
from oneaudit.utils.io import save_to_json
import json


def define_args(parent_parser):
    clean_leaks = parent_parser.add_parser('clean', help='This module will try to reduce the number of junk in your leaked credentials.')
    clean_leaks.add_argument('-i', metavar='input.json', dest='input_file', help='JSON file with leaked credentials.', required=True)
    clean_leaks.add_argument('-o', metavar='output.json', dest='output_file', help='Export results as JSON.', required=True)
    args_verbose_config(clean_leaks)


def censor_password(password, mode):
    """
    Input: toto1
    => to**1 if we censor and keep the start (mode=0)
    => t**o1 if we censor and keep the end (mode=1)
    => t***1 if we censor and keep neither (mode=2)
    """
    password_length = len(password)
    if password_length <= 1:
        return '*' if password_length == 1 else ''
    if password_length <= 3:
        return password[0] + "*" * (password_length-1)
    if password_length == 4 or mode == 2:
        return password[0] + "*" * (password_length-2) + password[-1]
    if mode == 0:
        first, second, last = password[0], password[1], password[-1]
        return first + second + '*' * (password_length - 3) + last
    elif mode == 1:
        first, before_last, last = password[0], password[-2], password[-1]
        return first + '*' * (password_length - 3) + before_last + last
    else:
        raise ValueError(f"Invalid value for mode: {mode}.")


def clean_credentials(credentials, logger=None):
    """
    Passwords too long or too short are unlikely to be of any use
    (some are junk/most likely from very old breaches, or even censored hashes)

    We also want to fix the date of each breach to the most likely, and remove duplicates.
    """
    possible_trails = ["", None] + [chr(i) for i in range(0, 255)]
    logger = logger if logger else get_project_logger()

    for credential in credentials:
        if credential['breaches']:
            valid_breaches = {}
            for breach in credential['breaches']:
                source, date, description = breach['source'], breach['date'], breach['description']
                # Ignore breaches like this
                if source == 'unknown' and date == 'unknown':
                    continue
                # Some breaches are missing the domain name
                for tld in [".com"]:
                    if source + tld in valid_breaches:
                        source += tld
                        break
                    if source.split(tld)[0] in valid_breaches:
                        key = source.split(tld)[0]
                        valid_breaches[source] = valid_breaches[key]
                        del valid_breaches[key]
                        break

                # We keep the earliest leak, as to avoid "fake" dates
                if source in valid_breaches:
                    other_date, other_description = valid_breaches[source]
                    if not date:
                        continue
                    if not other_date or other_date > date:
                        valid_breaches[source] = date, description if description else other_description
                else:
                    valid_breaches[source] = date, description
            credential['breaches'] = [BreachData(k, date, desc) for k, (date, desc) in valid_breaches.items()]

        if not credential['passwords'] and not credential['censored_passwords']:
            continue

        passwords = [p for p in credential['passwords'] if 4 <= len(p) < 25]
        known_censored_passwords = {}
        unknown_censored_passwords = []
        new_passwords = passwords

        while new_passwords:
            passwords_to_process = new_passwords
            new_passwords, unknown_censored_passwords = [], []

            for know_password in passwords_to_process:
                for trail in possible_trails:
                    # We remove the last character, or add a trail
                    if trail is None:
                        password = know_password[:-1]
                    else:
                        password = know_password + trail

                    # And we test all variants
                    for censor_mode in range(0, 3):
                        censored = censor_password(password, censor_mode)
                        known_censored_passwords[censored] = password
                        known_censored_passwords[censored[0].lower() + censored[1:]] = password[0].lower() + password[1:]
                        known_censored_passwords[censored[0].upper() + censored[1:]] = password[0].upper() + password[1:]

            for censored_password in credential['censored_passwords']:
                if censored_password in known_censored_passwords:
                    candidate = known_censored_passwords[censored_password]
                    if candidate not in passwords:
                        new_passwords.append(candidate)
                        passwords.append(candidate)
                    continue
                if not 4 <= len(censored_password) < 25:
                    continue
                unknown_censored_passwords.append(censored_password)

        # If we knew of every censored hash, we remove them
        credential['passwords'] = [p for p in set(passwords) if p != "(null)"]
        credential['censored_passwords'] = unknown_censored_passwords
        if unknown_censored_passwords and logger:
            for unknown_censored_password in unknown_censored_passwords:
                logger.warning(f"Uknown censored password {unknown_censored_password} for {credential['passwords']}")

    return credentials


def run(args):
    args_parse_parse_verbose(args)
    return compute_result(args, None)

def compute_result(args, _):
    args_parse_parse_verbose(args)

    with open(args.input_file, 'r') as file_data:
        data = json.load(file_data)
        credentials = data['credentials']

    data['credentials'] = clean_credentials(credentials)

    save_to_json(args.output_file, data)

    return data
