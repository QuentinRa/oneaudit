from oneaudit.utils.logs import args_verbose_config, args_parse_parse_verbose
from json import load as json_load
from zxcvbn import zxcvbn
from sys import maxsize
from os import mkdir
from os.path import join, exists


def define_args(parent_parser):
    export_leaks = parent_parser.add_parser('wordlist', help='Export passwords in multiple wordlists, 2 creds per user, per wordlist.')
    export_leaks.add_argument('-i', metavar='input.json', dest='input_file', help='JSON file with leaked credentials.', required=True)
    export_leaks.add_argument('-c', metavar='company_name', dest='token', help='Company name, if you want to prioritize testing passwords that contain the company name.')
    export_leaks.add_argument('-r', dest='reverse', action='store_true', help='The most complex passwords are tested last (default to first).')
    export_leaks.add_argument('-o', metavar='output', dest='output_folder', help='Export results in this folder.', required=True)
    args_verbose_config(export_leaks)


def password_complexity(token, password):
    return zxcvbn(password)["guesses"] if token and token not in password.lower() else maxsize


def run(args):
    args_parse_parse_verbose(args)

    with open(args.input_file, 'r') as file_data:
        data = json_load(file_data)
        credentials = data['credentials']

    token = args.token.lower() if args.token else None
    creds_per_wordlist = [[]]
    creds_per_wordlist_length = 0
    for credential in credentials:
        if not credential['passwords']:
            continue
        login = credential['login']
        passwords = credential['passwords']
        passwords = sorted(passwords, key=lambda password: password_complexity(token, password), reverse=not args.reverse)
        password_count = len(passwords)
        for password_index in range(0, password_count):
            wordlist_index = password_index // 2  if password_index > 0 else 0

            if wordlist_index > creds_per_wordlist_length:
                creds_per_wordlist.append([])
                creds_per_wordlist_length += 1

            creds_per_wordlist[wordlist_index].append((login, passwords[password_index]))

    if not exists(args.output_folder):
        mkdir(args.output_folder)

    for wordlist_index, wordlist_entries in enumerate(creds_per_wordlist):
        with open(join(args.output_folder, f"wordlist{wordlist_index}.lst"), "w") as output_file:
            output_file.writelines("\n".join([f'{username}:{password}' for (username, password) in wordlist_entries]))
