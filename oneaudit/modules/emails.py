import argparse
import json
import logging

import oneaudit.api
import oneaudit.api.osint
import oneaudit.utils

class OSINTSingleEmail:
    def __init__(self, args):
        oneaudit.utils.args_parse_parse_verbose(self, args)
        oneaudit.api.args_parse_api_config(self, args)
        self.email = args.email_address
        self.output_file = args.output

class OSINTListEmail:
    def __init__(self, args):
        oneaudit.utils.args_parse_parse_verbose(self, args)
        oneaudit.api.args_parse_api_config(self, args)
        self.input_file = args.source
        self.output_file = args.output

class OSINTFuzzEmail:
    def __init__(self, args):
        oneaudit.utils.args_parse_parse_verbose(self, args)
        # self.input_file = args.source
        # self.output_file = args.output


def parse_args(parser: argparse.ArgumentParser, module_parser: argparse.ArgumentParser):
    submodule_parser = module_parser.add_subparsers(dest='scope', help="Type of action", required=True)

    # LinkedIn
    email_module = submodule_parser.add_parser('check')
    email_module_action = email_module.add_subparsers(dest='action', help="Action to perform.", required=True)

    email_single = email_module_action.add_parser("single", help='Check a single mail address.')
    email_single.add_argument('-d', '--email', dest='email_address', help='For example, "john.deo@example.comm".', required=True)
    email_single.add_argument('-o', '--output', metavar='output.json', dest='output', help='Export results as JSON.', required=True)
    oneaudit.api.args_api_config(email_single)
    oneaudit.utils.args_verbose_config(email_single)

    email_list = email_module_action.add_parser("list", help='Check multiple emails in a row')
    email_list.add_argument('-s', '--file', dest='source', help="The list of emails (one email per line).", required=True)
    email_list.add_argument('-o', '--output', metavar='output.json', type=str, dest='output', help='Export results as JSON.', required=True)
    oneaudit.api.args_api_config(email_list)
    oneaudit.utils.args_verbose_config(email_list)

    email_fuzz = email_module_action.add_parser("fuzz", help="Fuzz a single user or a list of users with different formats base on the target's identity.")
    #email_fuzz.add_argument('-s', '--source', dest='source', choices=['rocketreach'], help="The input file source.", required=True)
    #email_fuzz.add_argument('-f', '--filter', dest='filter', type=str, help="A case-insensitive string such as 'LinkedIn' to only keep current employees.", required=True)
    #email_fuzz.add_argument('-i', '--input', metavar='export.json', type=str, dest='input', help='Exported results from one of the supported APIs.', required=True)
    #email_fuzz.add_argument('-o', '--output', metavar='output.json', type=str, dest='output', help='Export results as JSON.', required=True)
    oneaudit.utils.args_verbose_config(email_fuzz)

    return parser.parse_args()


def run(parser, module_parser):
    args = parse_args(parser, module_parser)
    logger = logging.getLogger("oneaudit")
    if args.scope == 'check':
        if args.action == 'single':
            args = OSINTSingleEmail(args)
            version = 1.0
            provider = oneaudit.api.osint.OSINTProviderManager(args.api_keys)
            results = provider.get_single_email(args.email)
            
        elif args.action == 'list':
            args = OSINTListEmail(args)
            version = 1.0
            provider = oneaudit.api.osint.OSINTProviderManager({}, cache_only=True)
            try:
                with open(args.input_file, 'r', encoding='utf-8') as input_file:
                    results = provider.get_multiple_email(input_file)
            except (FileNotFoundError, json.JSONDecodeError) as e:
                logger.error(f"[+] Failed to parse results: '{e}'.")
                return

        elif args.action == 'fuzz':
            args = OSINTFuzzEmail(args)
            # provider = oneaudit.api.osint.OSINTProviderManager(args.api_keys)
            # results = provider.export_records(args.file_source, args.profile_list_id)
            version = 1.0


        with open(args.output_file, 'w') as output_file:
            json.dump({
                "version": version,
                "entries": results,
            }, output_file, cls=oneaudit.modules.GenericObjectEncoder, indent=4)
