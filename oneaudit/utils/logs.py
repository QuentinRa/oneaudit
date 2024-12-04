from argparse import ArgumentParser
from colorlog import ColoredFormatter
from sys import stdout
import logging

_project_logger = None

def args_verbose_config(parser: ArgumentParser):
    verbosity_parser = parser.add_mutually_exclusive_group()
    verbosity_parser.add_argument('-v', dest='is_info', action='store_true', help='Info verbosity level.')
    verbosity_parser.add_argument('-vv', dest='is_debug', action='store_true', help='Debug verbosity level.')
    parser.add_argument('--log-file', dest='log_file', type=str, help='Log file to write logs.')


def args_parse_parse_verbose(args):
    log_level = logging.DEBUG if args.is_debug else logging.INFO if args.is_info else logging.WARNING
    get_project_logger(log_level, args.log_file)


def get_project_logger(log_level=logging.INFO, log_file=None):
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

        if log_file:
            formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
            file_handler = logging.FileHandler(log_file)
            file_handler.setFormatter(formatter)
            file_handler.setLevel(log_level)
            _project_logger.addHandler(file_handler)

    return _project_logger
