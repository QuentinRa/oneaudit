from oneaudit.api.osint import OSINTProviderManager
from oneaudit.utils import args_verbose_config, args_parse_parse_verbose
from logging import getLogger
import json

class OSINTParseLinkedInProgramData:
    def __init__(self, args):
        args_parse_parse_verbose(self, args)
        self.file_source = args.source
        self.filter = args.filter.lower()
        self.input_file = args.input
        self.output_file = args.output

def define_args(parent_parser):
    linkedin_parse = parent_parser.add_parser("parse", help='Parse exported results from OSINT tools into JSON usable by this toolkit.')
    linkedin_parse.add_argument('-s', '--source', dest='source', choices=['rocketreach'], help="The input file source.", required=True)
    linkedin_parse.add_argument('-f', '--filter', dest='filter', type=str, help="A case-insensitive string such as 'LinkedIn' to only keep current employees.", required=True)
    linkedin_parse.add_argument('-i', '--input', metavar='export.json', type=str, dest='input', help='Exported results from one of the supported APIs.', required=True)
    linkedin_parse.add_argument('-o', '--output', metavar='output.json', type=str, dest='output', help='Export results as JSON.', required=True)
    args_verbose_config(linkedin_parse)

def run(args):
    args = OSINTParseLinkedInProgramData(args)
    version = 1.0
    provider = OSINTProviderManager({}, cache_only=True)
    try:
        with open(args.input_file, 'r', encoding='utf-8') as input_file:
            results = provider.parse_records(args.file_source, args.filter, input_file)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        getLogger('oneaudit').error(f"[+] Failed to parse results: '{e}'.")
        return

    with open(args.output_file, 'w') as output_file:
        json.dump({
            "version": version,
            "entries": results,
        }, output_file, indent=4)