from oneaudit.api import args_api_config, args_parse_api_config
from oneaudit.api.osint import OSINTProviderManager
from oneaudit.utils import args_verbose_config, args_parse_parse_verbose
import json


class OSINTDownloadLinkedInProgramData:
    def __init__(self, args):
        args_parse_parse_verbose(self, args)
        args_parse_api_config(self, args)
        self.file_source = args.source
        self.profile_list_id = args.target
        self.output_file = args.output


def define_args(parent_parser):
    linkedin_export = parent_parser.add_parser("export", help='Export lists of profiles')
    linkedin_export.add_argument('-s', '--source', dest='source', choices=['rocketreach'], help="The target API.", required=True)
    linkedin_export.add_argument('-t', '--target', dest='target', type=str, help="The target profile list identifier.", required=True)
    linkedin_export.add_argument('-o', '--output', metavar='output.json', type=str, dest='output', help='Export results as JSON.', required=True)
    args_api_config(linkedin_export)
    args_verbose_config(linkedin_export)


def run(args):
    args = OSINTDownloadLinkedInProgramData(args)
    provider = OSINTProviderManager(args.api_keys)
    results = provider.export_records(args.file_source, args.profile_list_id)
    version = 1.0
    with open(args.output_file, 'w') as output_file:
        json.dump({
            "version": version,
            "entries": results,
        }, output_file, indent=4)