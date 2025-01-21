from oneaudit.api.utils.caching import args_api_config, args_parse_api_config
from oneaudit.api.osint.hosts.manager import OneAuditHostScanningAPIManager
from oneaudit.utils.logs import args_verbose_config, args_parse_parse_verbose
from oneaudit.utils.io import save_to_json
from json import load


def define_args(parent_parser):
    dump_subdomains = parent_parser.add_parser("scan", help='')
    dump_subdomains.add_argument('target_ips', nargs='+', help='IPs to scan, such as 127.0.0.1/24 or 127.0.0.1.')
    dump_subdomains.add_argument('-o', metavar='output.json', dest='output_file', help='Export results as JSON.', required=True)
    dump_subdomains.add_argument('-r', metavar='domains.json', dest='domains_file', default=None, help='Domain resolution information.')
    args_api_config(dump_subdomains)
    args_verbose_config(dump_subdomains)


def run(args):
    args_parse_parse_verbose(args)
    api_keys = args_parse_api_config(args)
    return compute_result(args, api_keys)

def compute_result(args, api_keys):
    manager = OneAuditHostScanningAPIManager(api_keys)

    # Map IPs to Domain(s)
    resolve_domains = {}
    if args.domains_file:
        with open(args.domains_file, 'r') as input_file:
            for d in load(input_file)["domains"]:
                ip_address = d['ip_address']
                if not ip_address:
                    continue
                if ip_address not in resolve_domains:
                    resolve_domains[ip_address] = []
                resolve_domains[ip_address].append(d['domain_name'])

    result = {
        'version': 1.0,
        'hosts': manager.scan_hosts(args.target_ips, resolve_domains)
    }
    save_to_json(args.output_file, result)
    return result
