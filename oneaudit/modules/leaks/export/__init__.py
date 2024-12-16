from oneaudit.modules.leaks.export import report
from oneaudit.modules.leaks.export import hashes
from oneaudit.modules.leaks.export import wordlist
from oneaudit.utils import args_call_target

def define_args(parent_parser):
    export_module = parent_parser.add_parser('export', help='Export utilities.')

    # Add actions we can perform related to leaks
    export_module_action = export_module.add_subparsers(dest='action_type', help="Which export module to use.", required=True)
    report.define_args(export_module_action)
    hashes.define_args(export_module_action)
    wordlist.define_args(export_module_action)


def run(args):
    # Call the 'run' method on the target 'action_type' object
    args_call_target(globals(), args, 'action_type', 'run')
