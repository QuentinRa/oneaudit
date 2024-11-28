from oneaudit.utils.logs import args_verbose_config, args_parse_parse_verbose, get_project_logger
from oneaudit.utils.io import save_to_json
from time import time
from os.path import exists

import cmd
import json


class LeaksCredentialProcessor(cmd.Cmd):
    intro = "Welcome to the leaks credential processor. Type 'help' for a list of commands."
    prompt = "(leak) "

    def __init__(self, args):
        super().__init__()
        args_parse_parse_verbose(args)
        with open(args.input_file, 'r') as file_data:
            self.credentials = json.load(file_data)['credentials']
        self.index = -1
        self.output_file = args.output_file
        self.new_credentials = {}
        self.logger = get_project_logger()
        if exists(self.output_file):
            if args.should_resume_process:
                try:
                    with open(self.output_file, 'r') as file_data:
                        data = json.load(file_data)
                        for entry in data['credentials']:
                            self.new_credentials[entry['login']] = entry['passwords']
                        self.index = int(data.get("index", 0))
                except json.JSONDecodeError as e:
                    self.logger.warning("Could not resume from output file")
                    self.logger.warning(e)
            else:
                self.logger.warning("Output file already exists.")
                self.output_file += "." + str(time())

    def do_next(self, arg):
        if self.index < len(self.credentials):
            self.index += 1
            credential = self.credentials[self.index]
            passwords = credential['passwords']+credential['censored_logins']
            if not passwords:
                return self.do_next(arg)
            print(f"Processing {credential['login']}")
            for i, password in enumerate(passwords, start=1):
                print(f"{i}. {password}")
            print()
        else:
            print("No more credentials to skip.")

    def do_exit(self, _):
        save_to_json(self.output_file, {
            "version": 1.0,
            "index": self.index,
            "credentials": [
                {
                    "login": email,
                    "passwords": passwords
                }
                for email, passwords in self.new_credentials.items()
            ]
        })
        return True

    def _keep_password(self, index):
        if 0 <= self.index < len(self.credentials):
            credential = self.credentials[self.index]
            passwords = credential['passwords']+credential['censored_logins']
            index = index - 1
            if index < len(passwords):
                key = credential['login']
                if key not in self.new_credentials:
                    self.new_credentials[key] = []
                self.new_credentials[key].append(passwords[index])
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


def define_args(parent_parser):
    clean_leaks = parent_parser.add_parser('clean', help='Select which passwords to keep.')
    clean_leaks.add_argument('-i', metavar='input.json', dest='input_file', help='JSON file with leaked credentials.', required=True)
    clean_leaks.add_argument('-o', metavar='output.json', dest='output_file', help='Export results as JSON.', required=True)
    clean_leaks.add_argument('-r', action='store_true', dest='should_resume_process', help='Start working for the previous output file.')
    args_verbose_config(clean_leaks)


def run(args):
    try:
        processor = LeaksCredentialProcessor(args)
        processor.cmdloop()
    except KeyboardInterrupt:
        pass

