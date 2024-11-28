from oneaudit.modules.leaks import parse
from oneaudit.modules.leaks import download
from oneaudit.modules.leaks import clean
from oneaudit.utils import args_call_target


def define_args(parent_parser):
    leaks_module = parent_parser.add_parser('leaks', help='Investigate data breaches')

    # Add actions we can perform related to leaks
    leaks_module_action = leaks_module.add_subparsers(dest='action', help="Action to perform.", required=True)
    parse.define_args(leaks_module_action)
    download.define_args(leaks_module_action)
    clean.define_args(leaks_module_action)


def run(args):
    # Call the 'run' method on the target 'action' object
    args_call_target(globals(), args, 'action', 'run')
