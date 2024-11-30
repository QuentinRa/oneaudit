from oneaudit.modules.socosint import linkedin
from oneaudit.utils import args_call_target


def define_args(parent_parser):
    socosint_module = parent_parser.add_parser('socosint', help='Social Networks OSINT')

    # Add Social Networks
    submodule_parser = socosint_module.add_subparsers(dest='scope', help="Target Social Networks", required=True)
    linkedin.define_args(submodule_parser)


def run(args):
    # Call the 'run' method on the target 'scope' object
    args_call_target(globals(), args, 'scope', 'run')
