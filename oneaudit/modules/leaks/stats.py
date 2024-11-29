from oneaudit.api.utils.caching import args_parse_api_config
from oneaudit.api.leaks.manager import OneAuditLeaksAPIManager
from oneaudit.utils.logs import args_verbose_config, args_parse_parse_verbose
from prettytable import PrettyTable
from json import load


def define_args(parent_parser):
    download_leaks = parent_parser.add_parser('stats', description='XXX')
    download_leaks.add_argument('-i', metavar='input.json', dest='input_file', help='JSON file with known data about targets.', required=True)
    download_leaks.add_argument('--cache', metavar='.cache', dest='cache_folder', help='Path to the cache folder used to cache requests.', required=True)
    args_verbose_config(download_leaks)


def run(args):
    args.api_config = None
    args_parse_parse_verbose(args)
    api_keys = args_parse_api_config(args)

    # Load Credentials
    with open(args.input_file, 'r') as file_data:
        credentials = load(file_data)['credentials']

    # Inspect them
    provider = OneAuditLeaksAPIManager(api_keys, True)
    stats = provider.compute_stats(credentials)
    print()

    table = PrettyTable()
    table.field_names = ["field \\ provider"] + [f'{name}' for (t, _) in list(stats.values())[:1] for name in t.keys()]

    for attribute, (attribute_stats, total_count) in stats.items():
        table_data = [attribute]
        for provider_name, provider_stats in attribute_stats.items():
            all_stats, exclusive = provider_stats['all'], provider_stats['exclusive']
            if all_stats == 0:
                table_data.append("x")
                continue
            percent1, percent2 = (all_stats / total_count) * 100, (exclusive / total_count) * 100
            message = (str(int(percent1)) if percent1.is_integer() else f'{percent1:.1f}') + '%'
            if percent2 != percent1:
                message += " (☆ " + (str(int(percent2)) if percent2.is_integer() else f"{percent2:.1f}") + '%)'
            table_data.append(message)

        table.add_row(table_data)

    print(table)
    print()
    print("Note: Percentages marked with a star (☆) are representing the percentage of results exclusive to this API.")
