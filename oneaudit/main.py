#!/usr/bin/env python3
import argparse
import sys
import logging


def main():
    parser = argparse.ArgumentParser(description="oneaudit utilities")
    module_parser = parser.add_subparsers(dest='module', required=True)
    leaks_module = module_parser.add_parser('leaks', help='Clean a JSON of leaked passwords.')
    ntlm_module = module_parser.add_parser('ntlm', help='Generate NTLM hashes from wordlist')
    socosint_module = module_parser.add_parser('socosint', help='Social Networks OSINT')
    email_module = module_parser.add_parser('email', help='Email verifier')

    module = sys.argv[1] if len(sys.argv) >= 2 else None
    if module is None or module in ["-h"]:
        parser.parse_known_args()

    if module == 'ntlm':
        import oneaudit.modules.ntlm
        oneaudit.modules.ntlm.run(parser, ntlm_module)
    elif module == 'leaks':
        import oneaudit.modules.leaks
        oneaudit.modules.leaks.run(parser, leaks_module)
    elif module == 'socosint':
        import oneaudit.modules.socosint
        oneaudit.modules.socosint.run(parser, socosint_module)
    elif module == 'email':
        import oneaudit.modules.emails
        oneaudit.modules.emails.run(parser, email_module)
    else:
        print(f"No such module: {module}.")
        sys.exit(2)


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        logger = logging.getLogger('oneaudit')
        logger.error(e)
        logger.error("Program was terminated due to an exception.")
