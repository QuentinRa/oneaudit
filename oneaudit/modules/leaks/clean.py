import cmd
import json
import os
import time
import oneaudit.utils.logs


class LeaksCleanProgramData:
    def __init__(self, args):
        oneaudit.utils.logs.args_parse_parse_verbose(args)
        with open(args.input, 'r') as file_data:
            self.data = json.load(file_data)
        self.output_file = args.output
        self.should_resume_process = args.resume_flag


class LeaksCredentialProcessor(cmd.Cmd):
    intro = "Welcome to the leaks credential processor. Type 'help' for a list of commands."
    prompt = "(leak) "

    def __init__(self, args: LeaksCleanProgramData):
        super().__init__()
        self.credentials = args.data.get('credentials', [])
        self.index = -1
        self.output_file = args.output_file
        self.new_credentials = {}
        if os.path.exists(self.output_file):
            if args.should_resume_process:
                try:
                    with open(self.output_file, 'r') as file_data:
                        data = json.load(file_data)
                        for entry in data['credentials']:
                            self.new_credentials[entry['login']] = entry['passwords']
                        self.index = int(data.get("index", 0))
                except json.JSONDecodeError:
                    pass
            else:
                self.output_file += "." + str(time.time())

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


def define_args(parent_parser):
    clean_leaks = parent_parser.add_parser('clean', help='Select which passwords to keep.')
    clean_leaks.add_argument('-i', metavar='input.json', dest='input', help='JSON file with leaked credentials.', required=True)
    clean_leaks.add_argument('-o', metavar='output.json', dest='output', help='Export results as JSON.', required=True)
    clean_leaks.add_argument('-r', action='store_true', dest='resume_flag', help='Start working for the previous output file.')
    oneaudit.utils.logs.args_verbose_config(clean_leaks)


def run(args):
    processor = LeaksCredentialProcessor(LeaksCleanProgramData(args))
    processor.cmdloop()
