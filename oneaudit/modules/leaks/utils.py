from oneaudit.api.utils.caching import args_api_config, args_parse_api_config
from oneaudit.api.leaks.manager import OneAuditLeaksAPIManager
from oneaudit.api.leaks import LeakProviderUtilities
from oneaudit.utils.logs import args_verbose_config, args_parse_parse_verbose


def define_args(parent_parser):
    utils_leaks = parent_parser.add_parser('utils', help='Convert passwords to the given hash format')
    utils_leaks.add_argument('-t', metavar='target_api', dest='target_api', help='Only enable this API.', required=True)
    utils_leaks.add_argument('-c', metavar='operation', dest='operation', choices=LeakProviderUtilities._member_names_, help='Operation to perform on this API', required=True)
    args_api_config(utils_leaks)
    args_verbose_config(utils_leaks)


def run(args):
    args_parse_parse_verbose(args)
    api_keys = args_parse_api_config(args)
    api_keys = { args.target_api: api_keys.get(args.target_api) }

    manager = OneAuditLeaksAPIManager(api_keys, can_use_cache_even_if_disabled=False)
    providers = [provider for provider in manager.providers if provider.api_name == args.target_api]
    if not providers:
        raise Exception(f"No such provider: {args.target_api}")

    provider = providers[0]
    provider.utilities(args.operation)
