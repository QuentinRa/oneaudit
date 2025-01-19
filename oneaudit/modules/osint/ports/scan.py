from oneaudit.api.utils.caching import args_api_config, args_parse_api_config
from oneaudit.api.osint.ports.manager import OneAuditPortScanningAPIManager
from oneaudit.utils.logs import args_verbose_config, args_parse_parse_verbose
from oneaudit.utils.io import save_to_json


def define_args(parent_parser):
    dump_subdomains = parent_parser.add_parser("scan", help='')
    dump_subdomains.add_argument('target_ips', nargs='+', help='IPs to scan, such as 127.0.0.1/24 or 127.0.0.1.')
    dump_subdomains.add_argument('-o', metavar='output.json', dest='output_file', help='Export results as JSON.', required=True)
    args_api_config(dump_subdomains)
    args_verbose_config(dump_subdomains)


def run(args):
    args_parse_parse_verbose(args)
    api_keys = args_parse_api_config(args)
    return compute_result(args, api_keys)

def compute_result(args, api_keys):
    manager = OneAuditPortScanningAPIManager(api_keys)
    result = {
        'version': 1.0,
        'domains': manager.scan_ports(args.target_ips)
    }
    save_to_json(args.output_file, result)
    return result
