from oneaudit.modules.osint.emails import check
from oneaudit.utils import args_call_target

def define_args(parent_parser):
    email_module = parent_parser.add_parser('emails')

    # Add actions we can perform against this platform
    email_module_action = email_module.add_subparsers(dest='action', help="Action to perform.", required=True)
    check.define_args(email_module_action)

def run(args):
    # Call the 'run' method on the target 'action' object
    args_call_target(globals(), args, 'action', 'run')
