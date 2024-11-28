from oneaudit.utils import args_call_target


def define_args(parent_parser):
    utils_module = parent_parser.add_parser('utils', help='Bunch of utilities')
    utils_module_action = utils_module.add_subparsers(dest='action', help="Action to perform.", required=True)


def run(args):
    # Call the 'run' method on the target 'action' object
    args_call_target(globals(), args, 'action', 'run')
