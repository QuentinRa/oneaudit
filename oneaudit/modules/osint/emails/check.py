from oneaudit.api import args_api_config, args_parse_api_config
from oneaudit.utils.io import save_to_json
from oneaudit.utils.logs import args_verbose_config, args_parse_parse_verbose
from argparse import ArgumentError

def define_args(parent_parser):
    email_checker = parent_parser.add_parser("check", help='Verify if the target emails are valid.')
    input_source = email_checker.add_mutually_exclusive_group()
    input_source.add_argument('-t', '--email', dest='input_email', help='For example, "john.doe@example.comm".')
    input_source.add_argument('-f', '--file', dest='input_file', help="The list of emails (one email per line) to verify.")
    email_checker.add_argument('-o', '--output', metavar='output.json', type=str, dest='output_file', help='Export results as JSON.', required=True)
    args_api_config(email_checker)
    args_verbose_config(email_checker)


def run(args):
    args_parse_parse_verbose(args)
    api_keys = args_parse_api_config(args)

    if not args.input_email and not args.input_file:
        raise ArgumentError(None, "the following arguments are required: -e/--email or -f/--file.")
