from oneaudit.api.socosint.linkedin.manager import OneAuditLinkedInAPIManager
from oneaudit.utils.io import save_to_json
from oneaudit.utils.logs import args_verbose_config, args_parse_parse_verbose, get_project_logger
from json import JSONDecodeError


def define_args(parent_parser):
    linkedin_parse = parent_parser.add_parser("parse", help='Parse exported results from OSINT tools into JSON usable by this toolkit.')
    linkedin_parse.add_argument('-s', '--source', dest='api_name', choices=['rocketreach'], help="The input file source.", required=True)
    linkedin_parse.add_argument('-f', '--filter', dest='filters', type=str, action='append', help="A case-insensitive string such as 'LinkedIn' to only keep current employees.", required=True)
    linkedin_parse.add_argument('-i', '--input', metavar='export.json', type=str, dest='input_file', help='Exported results from one of the supported APIs.', required=True)
    linkedin_parse.add_argument('-o', '--output', metavar='output.json', type=str, dest='output_file', help='Export results as JSON.', required=True)
    args_verbose_config(linkedin_parse)


def run(args):
    args_parse_parse_verbose(args)
    args.filters = [f.lower() for f in args.filters if f]
    provider = OneAuditLinkedInAPIManager({args.api_name: "sb0"})
    try:
        with open(args.input_file, 'r', encoding='utf-8') as input_file:
            save_to_json(args.output_file, {
                "version": 1.0,
                "entries": provider.parse_records_from_export(args.api_name, args.filters, input_file),
            })
    except (FileNotFoundError, JSONDecodeError) as e:
        get_project_logger().error(f"[+] Failed to parse results: '{e}'.")
        return