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
        self.index = -1
        self.new_credentials = {}
        self.output_file = args.output_file

    def do_next(self, arg):
        if self.index < len(self.credentials):
            self.index += 1
            credential = self.credentials[self.index]
            print(f"Processing {credential['login']}")
            for i, password in enumerate(credential['passwords'], start=1):
                print(f"{i}. {password}")
            print()
        else:
            print("No more credentials to skip.")

    def do_exit(self, arg):
        credentials = [
            {
                "login": email,
                "passwords": passwords
            }
            for email, passwords in self.new_credentials.items()
        ]

        with open(self.output_file, 'w') as output_file:
            json.dump({
                "version": 1.0,
                "index": self.index,
                "credentials": credentials
            }, output_file, indent=4)

        return True

    def _keep_password(self, index):
        if 0 <= self.index < len(self.credentials):
            credential = self.credentials[self.index]
            index = index - 1
            if index < len(credential['passwords']):
                key = credential['login']
                if key not in self.new_credentials:
                    self.new_credentials[key] = []
                self.new_credentials[key].append(credential['passwords'][index])
                print("Kept:", self.new_credentials[key])
                return

        print("Invalid index")

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
        elif line.isnumeric():
            return self._keep_password(int(line))
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
