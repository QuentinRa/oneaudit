#!/usr/bin/env python3
from argparse import ArgumentParser
from oneaudit.modules import socosint, leaks, osint, utils
from oneaudit.utils import args_call_target
from oneaudit.utils.logs import get_project_logger


def main():
    parser = ArgumentParser(description="oneaudit utilities")

    # Load define modules
    module_parser = parser.add_subparsers(dest='module', required=True)
    leaks.define_args(module_parser)
    osint.define_args(module_parser)
    socosint.define_args(module_parser)
    utils.define_args(module_parser)

    # Parse args
    args = parser.parse_args()

    # Call the 'run' method on the target 'module'
    args_call_target(globals(), args, 'module', 'run')


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        logger = get_project_logger()
        logger.error(e)
        logger.error("Program was terminated due to an exception.")
        #raise e
