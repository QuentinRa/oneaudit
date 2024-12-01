from oneaudit.modules.osint.subdomains import dump
from oneaudit.utils import args_call_target


def define_args(parent_parser):
    subdomains = parent_parser.add_parser('subdomains')
    subdomains_action = subdomains.add_subparsers(dest='action', help="Action to perform.", required=True)
    dump.define_args(subdomains_action)


def run(args):
    # Call the 'run' method on the target 'action' object
    args_call_target(globals(), args, 'action', 'run')
