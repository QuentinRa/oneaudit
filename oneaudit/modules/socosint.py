import argparse
import json
import time
import rocketreach
import oneaudit.api
import oneaudit.utils


class OSINTScrapLinkedInProgramData:
    def __init__(self, args):
        oneaudit.utils.args_parse_parse_verbose(self, args)
        oneaudit.api.args_parse_api_config(self, args)
        self.company_name = args.company_domain
        self.output_file = args.output


class OSINTParseLinkedInProgramData:
    def __init__(self, args):
        oneaudit.utils.args_parse_parse_verbose(self, args)
        self.file_source = args.source
        self.input_file = args.input
        self.output_file = args.output


def parse_args(parser: argparse.ArgumentParser, module_parser: argparse.ArgumentParser):
    submodule_parser = module_parser.add_subparsers(dest='scope', description='Target platform')

    # LinkedIn
    linkedin_module = submodule_parser.add_parser('linkedin')
    linkedin_module_action = linkedin_module.add_subparsers(dest='action')

    linkedin_scrapper = linkedin_module_action.add_parser("scrap", description='Scrap LinkedIn to fetch user profiles.')
    linkedin_scrapper.add_argument('-d', '--domain', dest='company_domain', help='For example, "example.com".', required=True)
    linkedin_scrapper.add_argument('-o', '--output', metavar='output.json', dest='output', help='Export results as JSON.', required=True)
    oneaudit.api.args_api_config(linkedin_scrapper)
    oneaudit.utils.args_verbose_config(linkedin_scrapper)

    linkedin_parse = linkedin_module_action.add_parser("parse", description='Parse exported results from Lookups into JSON usable by this toolkit.')
    linkedin_parse.add_argument('-s', '--source', dest='source', choices=['rocketreach'], help="The input file source.")
    linkedin_parse.add_argument('-i', '--input', metavar='export.json', dest='input', help='Exported results from one of the supported APIs.', required=True)
    linkedin_parse.add_argument('-o', '--output', metavar='output.json', dest='output', help='Export results as JSON.', required=True)
    oneaudit.utils.args_verbose_config(linkedin_parse)

    return parser.parse_args()


def _rocketreach_fetch_records(args: OSINTScrapLinkedInProgramData):
    results = {
        "source": "rocketreach",
        "date": time.time(),
        "version": 1.0,
        "targets": []
    }

    api_key = args.api_keys.get("rocketreach", None)
    if not api_key:
        print("[!] RocketReach Skipped: API Key Missing.")
        return results

    rr = rocketreach.Gateway(rocketreach.GatewayConfig(api_key))
    s = rr.person.search().filter(current_employer=f'\"{args.company_name}\"')

    page = 0
    try:
        while True:
            cached_result_key = "rocketreach_" + args.company_name + "_" + str(page)
            data = oneaudit.api.get_cached_result("rocketreach", cached_result_key)
            if data is None:
                s = s.params(start=page * 100 + 1, size=100)
                result = s.execute()
                if result.is_success:
                    data = result.response.json()
                    oneaudit.api.set_cached_result(cached_result_key, data)
                else:
                    if result.response.status_code == 429:
                        wait = int(result.response.headers["retry-after"] if "retry-after" in result.response.headers else 2)
                        print(f"Waiting for {wait} seconds.")
                        time.sleep(wait)
                        continue
                    print(result.response.status_code)
                    print(result.response.headers)
                    print(result.response.text)
                    raise Exception(f'Error: {result.message}!', True)

            for profile in data["profiles"]:
                target_emails = profile["teaser"]["emails"] + profile["teaser"]["professional_emails"]
                target_emails = list(set(target_emails))
                results["targets"].append({
                    "full_name": profile["name"],
                    "linkedin_url": profile["linkedin_url"],
                    'birth_year': profile['birth_year'],
                    '_status': profile['status'],
                    '_count': len(target_emails),
                })

            pagination = data['pagination']
            if pagination['next'] > pagination['total']:
                break
            page += 1
    except Exception as e:
        print(e)
    return results


def _rocketreach_parse_records(args, input_file):
    results = {
        "source": "rocketreach",
        "date": time.time(),
        "version": 1.0,
        "targets": []
    }

    if args.file_source != 'rocketreach':
        return results
    entries = json.load(input_file)["records"]
    for entry in entries:
        emails = []
        for email in entry['emails']:
            if email['source'] == "predicted":
                if email['format_probability'] and email['format_probability'] < 35:
                    continue
                if email['confidence'] < 50:
                    continue
            emails.append(email['email'].lower())

        results["targets"].append({
            "first_name": entry["first_name"],
            "last_name": entry["last_name"],
            "linkedin_url": entry["linkedin_url"],
            'emails': emails,
        })
    return results


def run(parser, module_parser):
    args = parse_args(parser, module_parser)
    if args.scope == 'linkedin':
        results = []
        if args.action == 'scrap':
            args = OSINTScrapLinkedInProgramData(args)
            results.append(_rocketreach_fetch_records(args))
        elif args.action == 'parse':
            args = OSINTParseLinkedInProgramData(args)
            try:
                with open(args.input_file, 'r') as input_file:
                    results.append(_rocketreach_parse_records(args, input_file))
            except (FileNotFoundError, json.JSONDecodeError) as e:
                print(f"[+] Failed to parse results: '{e}'.")

        with open(args.output_file, 'w') as output_file:
            json.dump({
                "version": 1.1,
                "entries": results,
            }, output_file, indent=4)
