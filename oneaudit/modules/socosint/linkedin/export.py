from oneaudit.api.utils.caching import args_api_config, args_parse_api_config
from oneaudit.api.socosint.linkedin.manager import OneAuditLinkedInAPIManager
from oneaudit.utils.io import save_to_json
from oneaudit.utils.logs import args_verbose_config, args_parse_parse_verbose


def define_args(parent_parser):
    linkedin_export = parent_parser.add_parser("export", help='Export lists of profiles')
    linkedin_export.add_argument('-s', '--source', dest='file_source', choices=['rocketreach'], help="The target API.", required=True)
    linkedin_export.add_argument('-t', '--target', dest='profile_list_id', type=str, help="The target profile list identifier.", required=True)
    linkedin_export.add_argument('-o', '--output', metavar='output.json', type=str, dest='output_file', help='Export results as JSON.', required=True)
    args_api_config(linkedin_export)
    args_verbose_config(linkedin_export)


def run(args):
    args_parse_parse_verbose(args)
    api_keys = args_parse_api_config(args)
    provider = OneAuditLinkedInAPIManager(api_keys)
    save_to_json(args.output_file, {
        "version": 1.0,
        "entries": provider.export_records(args.file_source, args.profile_list_id),
    })