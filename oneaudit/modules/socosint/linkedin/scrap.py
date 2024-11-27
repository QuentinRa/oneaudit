from oneaudit.api import args_api_config, args_parse_api_config
from oneaudit.api.osint import OSINTProviderManager
from oneaudit.utils import args_verbose_config, args_parse_parse_verbose
import json


class OSINTScrapLinkedInProgramData:
    def __init__(self, args):
        args_parse_parse_verbose(self, args)
        args_parse_api_config(self, args)
        self.company_name = args.company_domain
        self.output_file = args.output

def define_args(parent_parser):
    linkedin_scrapper = parent_parser.add_parser("scrap", help='Scrap LinkedIn to fetch user profiles.')
    linkedin_scrapper.add_argument('-d', '--domain', dest='company_domain', help='For example, "example.com".', required=True)
    linkedin_scrapper.add_argument('-o', '--output', metavar='output.json', dest='output', help='Export results as JSON.', required=True)
    args_api_config(linkedin_scrapper)
    args_verbose_config(linkedin_scrapper)


def run(args):
    args = OSINTScrapLinkedInProgramData(args)
    provider = OSINTProviderManager(args.api_keys)
    with open(args.output_file, 'w') as output_file:
        json.dump({
            "version": 1.1,
            "entries": provider.fetch_records(args.company_name),
        }, output_file, indent=4)