#!/usr/bin/env python3
import argparse
import sys


def main():
    parser = argparse.ArgumentParser(description="oneaudit utilities")
    module_parser = parser.add_subparsers(dest='module', required=True)
    leaks_module = module_parser.add_parser('leaks', help='Clean a JSON of leaked passwords.')
    ntlm_module = module_parser.add_parser('ntlm', help='Generate NTLM hashes from wordlist')

    module = sys.argv[1] if len(sys.argv) >= 2 else None
    if module is None or module in ["-h"]:
        parser.parse_known_args()

    if module == 'ntlm':
        import oneaudit.modules.ntlm
        oneaudit.modules.ntlm.run(parser, ntlm_module)
    elif module == 'leaks':
        import oneaudit.modules.leaks
        oneaudit.modules.leaks.run(parser, leaks_module)
    else:
        print(f"No such module: {module}.")
        sys.exit(2)


if __name__ == "__main__":
    main()
