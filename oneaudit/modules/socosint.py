import argparse
import json
import logging

import oneaudit.api
import oneaudit.api.osint
import oneaudit.utils


class OSINTScrapLinkedInProgramData:
    def __init__(self, args):
        oneaudit.utils.args_parse_parse_verbose(self, args)
        oneaudit.api.args_parse_api_config(self, args)
        self.company_name = args.company_domain
        self.output_file = args.output


class OSINTParseLinkedInProgramData:
    def __init__(self, args):
        oneaudit.utils.args_parse_parse_verbose(self, args)
        self.file_source = args.source
        self.filter = args.filter.lower()
        self.input_file = args.input
        self.output_file = args.output


def parse_args(parser: argparse.ArgumentParser, module_parser: argparse.ArgumentParser):
    submodule_parser = module_parser.add_subparsers(dest='scope', help="Target Social Networks", required=True)

    # LinkedIn
    linkedin_module = submodule_parser.add_parser('linkedin')
    linkedin_module_action = linkedin_module.add_subparsers(dest='action', help="Action to perform.", required=True)

    linkedin_scrapper = linkedin_module_action.add_parser("scrap", help='Scrap LinkedIn to fetch user profiles.')
    linkedin_scrapper.add_argument('-d', '--domain', dest='company_domain', help='For example, "example.com".', required=True)
    linkedin_scrapper.add_argument('-o', '--output', metavar='output.json', dest='output', help='Export results as JSON.', required=True)
    oneaudit.api.args_api_config(linkedin_scrapper)
    oneaudit.utils.args_verbose_config(linkedin_scrapper)

    linkedin_parse = linkedin_module_action.add_parser("parse", help='Parse exported results from OSINT tools into JSON usable by this toolkit.')
    linkedin_parse.add_argument('-s', '--source', dest='source', choices=['rocketreach'], help="The input file source.")
    linkedin_parse.add_argument('-f', '--filter', dest='filter', type=str, help="A case-insensitive string such as 'LinkedIn' to only keep current employees.", required=True)
    linkedin_parse.add_argument('-i', '--input', metavar='export.json', type=str, dest='input', help='Exported results from one of the supported APIs.', required=True)
    linkedin_parse.add_argument('-o', '--output', metavar='output.json', type=str, dest='output', help='Export results as JSON.', required=True)
    oneaudit.utils.args_verbose_config(linkedin_parse)

    return parser.parse_args()


def run(parser, module_parser):
    args = parse_args(parser, module_parser)
    logger = logging.getLogger("oneaudit")
    if args.scope == 'linkedin':
        if args.action == 'scrap':
            args = OSINTScrapLinkedInProgramData(args)
            provider = oneaudit.api.osint.OSINTProviderManager(args.api_keys)
            results = provider.fetch_records(args.company_name)
            version = 1.1
        elif args.action == 'parse':
            args = OSINTParseLinkedInProgramData(args)
            version = 1.0
            provider = oneaudit.api.osint.OSINTProviderManager({}, cache_only=True)
            try:
                with open(args.input_file, 'r', encoding='utf-8') as input_file:
                    results = provider.parse_records(args.file_source, args.filter, input_file)
            except (FileNotFoundError, json.JSONDecodeError) as e:
                logger.error(f"[+] Failed to parse results: '{e}'.")
                return

        with open(args.output_file, 'w') as output_file:
            json.dump({
                "version": version,
                "entries": results,
            }, output_file, cls=oneaudit.modules.GenericObjectEncoder, indent=4)
