from oneaudit.modules.socosint.linkedin import scrap
from oneaudit.modules.socosint.linkedin import export
from oneaudit.modules.socosint.linkedin import parse
from oneaudit.utils import args_call_target


def define_args(parent_parser):
    linkedin_module = parent_parser.add_parser('linkedin')

    # Add actions we can perform against this platform
    linkedin_module_action = linkedin_module.add_subparsers(dest='action', help="Action to perform.", required=True)
    scrap.define_args(linkedin_module_action)
    export.define_args(linkedin_module_action)
    parse.define_args(linkedin_module_action)


def run(args):
    # Call the 'run' method on the target 'action' object
    args_call_target(globals(), args, 'action', 'run')
