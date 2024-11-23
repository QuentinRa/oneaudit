import argparse
import colorlog
import logging
import sys

def args_verbose_config(parser: argparse.ArgumentParser):
    verbose = parser.add_mutually_exclusive_group()
    verbose.add_argument('-v', dest='is_debug', action='store_true', help='Debug verbosity level.')

def args_parse_parse_verbose(obj, args):
    obj.log_level = logging.DEBUG if args.is_debug else logging.INFO
    project_logger = logging.getLogger('oneaudit')
    project_logger.setLevel(obj.log_level)

    console_handler = logging.StreamHandler(sys.stdout)
    formatter = colorlog.ColoredFormatter(
        '%(log_color)s%(asctime)s - %(name)s - %(levelname)s - %(message)s',
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
    project_logger.addHandler(console_handler)