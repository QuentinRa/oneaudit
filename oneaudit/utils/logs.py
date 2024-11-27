from argparse import ArgumentParser
from colorlog import ColoredFormatter
from sys import stdout
import logging

_project_logger = None

def args_verbose_config(parser: ArgumentParser):
    verbose = parser.add_mutually_exclusive_group()
    verbose.add_argument('-v', dest='is_debug', action='store_true', help='Debug verbosity level.')


def args_parse_parse_verbose(args):
    log_level = logging.DEBUG if args.is_debug else logging.INFO
    get_project_logger(log_level)


def get_project_logger(log_level=logging.INFO):
    global _project_logger
    if _project_logger is None:
        _project_logger = logging.getLogger('oneaudit')
        _project_logger.setLevel(log_level)

        console_handler = logging.StreamHandler(stdout)
        formatter = ColoredFormatter(
            '%(log_color)s%(asctime)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S',
            log_colors={
                'DEBUG': 'blue',
                'INFO': 'green',
                'WARNING': 'yellow',
                'ERROR': 'red',
                'CRITICAL': 'bold_red',
            }
        )
        console_handler.setFormatter(formatter)
        _project_logger.addHandler(console_handler)
    else:
        return _project_logger