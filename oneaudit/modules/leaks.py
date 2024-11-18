import argparse
import json


class LeaksProgramData:
    def __init__(self, args):
        with open(args.input, 'r') as file_data:
            self.data = json.load(file_data)
        self.output_file = args.output


def parse_args(parser: argparse.ArgumentParser, module_parser: argparse.ArgumentParser):
    module_parser.add_argument('-f', metavar='input.json', dest='input', help='JSON file with leaked credentials.', required=True)
    module_parser.add_argument('-o', metavar='output.json', dest='output', help='Export results as JSON.', required=True)
    args = parser.parse_args()
    return LeaksProgramData(args)


def run(parser, module_parser):
    args = parse_args(parser, module_parser)
