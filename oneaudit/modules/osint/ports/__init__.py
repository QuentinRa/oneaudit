from oneaudit.modules.osint.ports import scan
from oneaudit.utils import args_call_target


def define_args(parent_parser):
    port_scanning_module = parent_parser.add_parser('ports')

    # Add actions we can perform against this platform
    port_scanning_module_action = port_scanning_module.add_subparsers(dest='action', help="Action to perform.", required=True)
    scan.define_args(port_scanning_module_action)


def run(args):
    # Call the 'run' method on the target 'action' object
    args_call_target(globals(), args, 'action', 'run')
