from openpyxl.formatting.rule import FormulaRule
from openpyxl.styles import PatternFill
from openpyxl.worksheet.datavalidation import DataValidation
from oneaudit.api.utils.caching import args_api_config, args_parse_api_config
from oneaudit.utils.logs import args_verbose_config, args_parse_parse_verbose
from oneaudit.modules.osint.subdomains.dump import compute_result as dump_subdomains
from oneaudit.utils.sheet import create_workbook, workbook_add_sheet_with_table
from os.path import exists as file_exists
from os import makedirs


def define_args(parent_parser):
    automate_module = parent_parser.add_parser('automate', help='Automated Module')
    automate_module.add_argument('-d', '--domain', dest='company_domain', help='For example, "example.com".', required=True)
    automate_module.add_argument('-o', '--output', dest='output_folder', required=True)
    args_api_config(automate_module)
    args_verbose_config(automate_module)

def run(args):
    args_parse_parse_verbose(args)
    api_keys = args_parse_api_config(args)
    output_folder = f'{args.output_folder}/{args.company_domain}'

    if not file_exists(output_folder):
        makedirs(output_folder, exist_ok=True)

    workbook = create_workbook()
    green_fill = PatternFill(start_color="00FF00", end_color="00FF00", fill_type="solid")
    red_fill = PatternFill(start_color="FF0000", end_color="FF0000", fill_type="solid")

    # Subdomains
    args.output_file = f'{output_folder}/subdomains.json'
    data = dump_subdomains(args, api_keys)
    workbook_add_sheet_with_table(
        workbook=workbook,
        title="Subdomains",
        columns=["Domain", "IP", "Inspected", "Ports"],
        rows=[[d.domain_name, d.ip_address, False, "Not checked"] for d in data['domains']],
        sizes=(50, 25, 15, 15),
        validation_rules=[
            None,
            None,
            DataValidation(
                type="list",
                formula1='"TRUE,FALSE"',
                showDropDown=False
            ),
            None
        ],
        formatting_rules=[
            None,
            [FormulaRule(formula=['ISBLANK(B2)'], fill=red_fill)],
            [
                FormulaRule(formula=['C2=TRUE'], fill=green_fill),
                FormulaRule(formula=['C2=FALSE'], fill=red_fill)
            ],
            None
        ]
    )


    # Save
    args.output_file = f'{output_folder}/report.xlsx'
    workbook.save(args.output_file)


