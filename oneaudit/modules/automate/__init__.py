from openpyxl.formatting.rule import FormulaRule
from openpyxl.styles import PatternFill
from oneaudit.api.utils.caching import args_api_config, args_parse_api_config
from oneaudit.utils.logs import args_verbose_config, args_parse_parse_verbose, get_project_logger
from oneaudit.modules.osint.subdomains.dump import compute_result as dump_subdomains
from oneaudit.modules.osint.ports.scan import compute_result as port_scan
from oneaudit.utils.sheet import create_workbook, workbook_add_sheet_with_table
from os.path import exists as file_exists
from os import makedirs


def define_args(parent_parser):
    automate_module = parent_parser.add_parser('automate', help='Automated Module')
    automate_module.add_argument('-d', '--domain', dest='company_domain', help='For example, "example.com".', required=True)
    automate_module.add_argument('-s', '--scope', help='IPs to scan, comma-separated, such as <found>,127.0.0.1/24,127.0.0.1.')
    automate_module.add_argument('-o', '--output', dest='output_folder', required=True)
    args_api_config(automate_module)
    args_verbose_config(automate_module)

def run(args):
    args_parse_parse_verbose(args)
    api_keys = args_parse_api_config(args)
    logger = get_project_logger()
    output_folder = f'{args.output_folder}/{args.company_domain}'

    if not file_exists(output_folder):
        makedirs(output_folder, exist_ok=True)

    workbook = create_workbook()
    good_fill = PatternFill(start_color="C6EFCE", end_color="C6EFCE", fill_type="solid")
    neutral_fill = PatternFill(start_color="FFEB9C", end_color="FFEB9C", fill_type="solid")
    bad_fill = PatternFill(start_color="FFC7CE", end_color="FFC7CE", fill_type="solid")

    # Subdomains
    subdomain_output_file = f'{output_folder}/subdomains.json'
    args.output_file = subdomain_output_file
    data = dump_subdomains(args, api_keys)
    workbook_add_sheet_with_table(
        workbook=workbook,
        title="Subdomains",
        columns=["Domain", "IP", "ASN", "ASN Name", "ASN Range"],
        rows=[[d.domain_name, d.ip_address, d.asn['asn_id'] if d.asn else "", d.asn['asn_range'] if d.asn else "", d.asn['asn_name'] if d.asn else ""] for d in data['domains']],
        sizes=(50, 25, 10, 20, 15),
        validation_rules=[
            None,
            None,
            None,
            None,
            None,
        ],
        formatting_rules=[
            None,
            [FormulaRule(formula=['ISBLANK(B2)'], fill=bad_fill)],
            [FormulaRule(formula=['ISBLANK(C2)'], fill=bad_fill)],
            [FormulaRule(formula=['ISBLANK(D2)'], fill=bad_fill)],
            [FormulaRule(formula=['ISBLANK(E2)'], fill=bad_fill)],
        ],
        autowrap=False
    )

    # Open Ports
    if args.scope:
        port_scanning_output_file = f'{output_folder}/hosts.json'
        args.output_file = port_scanning_output_file
        args.target_ips = (args.scope  if "<found>" not in args.scope else args.scope.replace("<found>", ",".join(
            set([d.ip_address for d in data['domains'] if d.ip_address])
        ))).split(',')
        args.domains_file = subdomain_output_file
        data = port_scan(args, api_keys)
        workbook_add_sheet_with_table(
            workbook=workbook,
            title="Hosts",
            columns=["IP", "Port", "Domains", "Details"],
            rows=[[ip_address, port, '\n'.join(host['domains']), '\n'.join(host['details'])] for ip_address, host in data['hosts'].items() for port in (host['ports'] if host['ports'] else [None])],
            sizes=(25, 10, 50, 50),
            validation_rules=[
                None,
                None,
                None,
                None,
            ],
            formatting_rules=[
                None,
                [FormulaRule(formula=['ISBLANK(B2)'], fill=bad_fill)],
                None,
                None,
            ],
            autowrap=True,
        )
    else:
        logger.warning("Please use --scope to enable port scanning. To scan all IPs found during enumeration, use: -s '<found>'.")

    # DataValidation(
    #                 type="list",
    #                 formula1='"TRUE,FALSE"',
    #                 showDropDown=False
    #             ),
    # [
    #                 FormulaRule(formula=['C2=TRUE'], fill=green_fill),
    #                 FormulaRule(formula=['C2=FALSE'], fill=red_fill)
    #             ],
    # ws.merge_cells(start_row=1, start_column=1, end_row=len(ports_status), end_column=1)

    # Save
    args.output_file = f'{output_folder}/report.xlsx'
    workbook.save(args.output_file)


