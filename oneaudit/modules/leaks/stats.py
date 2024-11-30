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


def _add_to_column(columns, column_name, column_value):
    if column_name not in columns:
        columns[column_name] = [column_value]
    else:
        columns[column_name].append(column_value)


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
    table_data = {}

    for attribute, (attribute_stats, total_count) in stats.items():
        _add_to_column(table_data, "field \\ provider", attribute + " (" + str(total_count) + ")")
        for provider_name, provider_stats in attribute_stats.items():
            all_stats, exclusive = provider_stats['all'], provider_stats['exclusive']
            if all_stats == 0:
                _add_to_column(table_data, provider_name, None)
                continue
            percent1, percent2 = (all_stats / total_count) * 100, (exclusive / total_count) * 100
            message = (str(int(percent1)) if percent1.is_integer() else f'{percent1:.1f}') + '%'
            if percent2 != percent1:
                message += " (☆ " + (str(int(percent2)) if percent2.is_integer() else f"{percent2:.1f}") + '%)'
            _add_to_column(table_data, provider_name, message)

    for column_name, values in table_data.items():
        if all(value is None for value in values):
            continue
        table.add_column(column_name, ["x" if value is None else value for value in values])

    print(table)
    print()
    print("Note: Percentages marked with a star (☆) are representing the percentage of results exclusive to this API.")
