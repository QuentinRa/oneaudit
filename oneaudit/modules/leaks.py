import argparse
import cmd
import json


class LeaksProgramData:
    def __init__(self, args):
        with open(args.input, 'r') as file_data:
            self.data = json.load(file_data)
        self.output_file = args.output


class LeaksCredentialProcessor(cmd.Cmd):
    intro = "Welcome to the leaks credential processor. Type 'help' for a list of commands."
    prompt = "(leak) "

    def __init__(self, args: LeaksProgramData):
        super().__init__()
        self.credentials = args.data.get('credentials', [])
        self.index = 0
        self.new_credentials = []

    def do_next(self, arg):
        if self.index < len(self.credentials):
            credential = self.credentials[self.index]
            print(f"Processing {credential['login']}")
            print(f"Passwords: {', '.join(credential['passwords'])}")
            print()
            self.index += 1
        else:
            print("No more credentials to skip.")

    def do_exit(self, arg):
        print("Exiting.")
        return True

    def default(self, line):
        aliases = {
            'n': 'next',
            's': 'next',
            'q': 'exit',
            'quit': 'exit',
        }

        command = aliases.get(line.lower())
        if command:
            return self.onecmd(command)
        else:
            print(f"Unknown command or alias: {line}")


def parse_args(parser: argparse.ArgumentParser, module_parser: argparse.ArgumentParser):
    module_parser.add_argument('-f', metavar='input.json', dest='input', help='JSON file with leaked credentials.', required=True)
    module_parser.add_argument('-o', metavar='output.json', dest='output', help='Export results as JSON.', required=True)
    args = parser.parse_args()
    return LeaksProgramData(args)


def run(parser, module_parser):
    args = parse_args(parser, module_parser)
    processor = LeaksCredentialProcessor(args)
    processor.cmdloop()
