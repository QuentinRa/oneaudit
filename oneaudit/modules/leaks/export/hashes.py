from oneaudit.utils.logs import args_verbose_config, args_parse_parse_verbose, get_project_logger
from Crypto.Hash import MD4
import json


def define_args(parent_parser):
    export_leaks = parent_parser.add_parser('hashes', help='Export passwords to the given hash format')
    export_leaks.add_argument('-i', metavar='input.json', dest='input_file', help='JSON file with leaked credentials.', required=True)
    export_leaks.add_argument('-f', metavar='format', dest='hash_format', choices=['ntlm'], help='Select a hash format.', required=True)
    export_leaks.add_argument('-o', metavar='output.json', dest='output_file', help='Export results as JSON.', required=True)
    args_verbose_config(export_leaks)


def run(args):
    args_parse_parse_verbose(args)

    with open(args.input_file, 'r') as file_data:
        data = json.load(file_data)
        credentials = data['credentials']

    ntlm_hash = lambda p : MD4.new(p.encode('utf-16le')).hexdigest().lower()
    hashes = [ntlm_hash(password) for credential in credentials for password in credential['passwords']]

    with open(args.output_file, 'w') as output_file:
        output_file.writelines('\n'.join(hashes))
