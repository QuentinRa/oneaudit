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


def parse_args(parser: argparse.ArgumentParser, module_parser: argparse.ArgumentParser):
    oneaudit.api.args_api_config(email_single)
    oneaudit.utils.args_verbose_config(email_single)
    oneaudit.api.args_api_config(email_list)
    oneaudit.utils.args_verbose_config(email_list)

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


        with open(args.output_file, 'w') as output_file:
            json.dump({
                "version": version,
                "entries": results,
            }, output_file, cls=oneaudit.modules.GenericObjectEncoder, indent=4)
