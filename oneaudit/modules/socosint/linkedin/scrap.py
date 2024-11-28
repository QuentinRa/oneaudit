from oneaudit.api import args_api_config, args_parse_api_config
from oneaudit.api.osint import OSINTProviderManager
from oneaudit.utils.io import save_to_json
from oneaudit.utils.logs import args_verbose_config, args_parse_parse_verbose


def define_args(parent_parser):
    linkedin_scrapper = parent_parser.add_parser("scrap", help='Scrap LinkedIn to fetch user profiles.')
    linkedin_scrapper.add_argument('-d', '--domain', dest='company_name', help='For example, "example.com".', required=True)
    linkedin_scrapper.add_argument('-t', '--target', dest='profile_list_id', type=str, help="The target profile list identifier such as 12345678 for RocketReach.")
    linkedin_scrapper.add_argument('-o', '--output', metavar='output.json', dest='output_file', help='Export results as JSON.', required=True)
    args_api_config(linkedin_scrapper)
    args_verbose_config(linkedin_scrapper)


def run(args):
    args_parse_parse_verbose(args)
    api_keys = args_parse_api_config(args)
    provider = OSINTProviderManager(api_keys)
    save_to_json(args.output_file, {
        "version": 1.1,
        "entries": provider.fetch_records(args.company_name),
    })