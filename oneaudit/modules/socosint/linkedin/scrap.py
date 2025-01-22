from oneaudit.api.utils.caching import args_api_config, args_parse_api_config
from oneaudit.api.socosint.linkedin.manager import OneAuditLinkedInAPIManager
from oneaudit.utils.io import save_to_json
from oneaudit.utils.logs import args_verbose_config, args_parse_parse_verbose


def define_args(parent_parser):
    linkedin_scrapper = parent_parser.add_parser("scrap", help='Scrap LinkedIn to fetch user profiles.')
    linkedin_scrapper.add_argument('-d', '--domain', dest='company_domain', help='For example, "example.com".', required=True)
    linkedin_scrapper.add_argument('-p', '--profile', dest='company_profile', help='For example, https://www.linkedin.com/company/microsoft')
    linkedin_scrapper.add_argument('-t', '--target', dest='target_profile_list_id', type=str, help="The target profile list identifier. Default to 'auto'. Ex: 12345678 for RocketReach.", default="auto")
    linkedin_scrapper.add_argument('-o', '--output', metavar='output.json', dest='output_file', help='Export results as JSON.', required=True)
    args_api_config(linkedin_scrapper)
    args_verbose_config(linkedin_scrapper)


def run(args):
    args_parse_parse_verbose(args)
    api_keys = args_parse_api_config(args)
    return compute_result(args, api_keys)

def compute_result(args, api_keys):
    provider = OneAuditLinkedInAPIManager(api_keys)
    result = {
        "version": 1.2,
        "entries": provider.search_employees_from_company_domain(args.company_domain, args.company_profile, args.target_profile_list_id),
    }
    save_to_json(args.output_file, result)
    return result
