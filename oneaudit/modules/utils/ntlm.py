import argparse
import json
import Crypto.Hash.MD4


class NTLMProgramData:
    def __init__(self, args):
        with open(args.input, 'r') as file_data:
            self.data = json.load(file_data)
        self.output_file = args.output


def parse_args(parser: argparse.ArgumentParser, module_parser: argparse.ArgumentParser):
    module_parser.add_argument('-f', metavar='input.json', dest='input', help='JSON file with leaked credentials.', required=True)
    module_parser.add_argument('-o', metavar='output.txt', dest='output', help='Export results as TXT.', required=True)
    args = parser.parse_args()
    return NTLMProgramData(args)


def run(parser, module_parser):
    args = parse_args(parser, module_parser)

    # Compute Hashes
    ntlm_hash = lambda p : Crypto.Hash.MD4.new(p.encode('utf-16le')).hexdigest().lower()
    result = []
    for entry in args.data['credentials']:
        result.extend(entry['passwords'])

    with open(args.output_file, 'w') as output_file:
        output_file.writelines("\n".join([ntlm_hash(p) for p in set(result)]))
