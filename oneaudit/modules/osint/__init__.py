from oneaudit.modules.osint import emails
from oneaudit.utils import args_call_target


def define_args(parent_parser):
    osint_module = parent_parser.add_parser('osint', help='OSINT Tools')

    # Add Social Networks
    submodule_parser = osint_module.add_subparsers(dest='element', help="The element we want to process.", required=True)
    emails.define_args(submodule_parser)


def run(args):
    # Call the 'run' method on the target 'element' object
    args_call_target(globals(), args, 'element', 'run')
