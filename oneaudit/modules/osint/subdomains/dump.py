from oneaudit.api.utils.caching import args_api_config, args_parse_api_config
from oneaudit.api.osint.dns.manager import OneAuditDNSAPIManager
from oneaudit.utils.logs import args_verbose_config, args_parse_parse_verbose
from oneaudit.utils.io import save_to_json


def define_args(parent_parser):
    dump_subdomains = parent_parser.add_parser("dump", help='')
    dump_subdomains.add_argument('-d', '--domain', dest='company_domain', help='For example, "example.com".', required=True)
    dump_subdomains.add_argument('-o', metavar='output.json', dest='output_file', help='Export results as JSON.', required=True)
    args_api_config(dump_subdomains)
    args_verbose_config(dump_subdomains)


def run(args):
    args_parse_parse_verbose(args)
    api_keys = args_parse_api_config(args)
    manager = OneAuditDNSAPIManager(api_keys)
    save_to_json(args.output_file, {
        'version': 1.0,
        'domains': manager.dump_subdomains(args.company_domain)
    })
