import argparse
import json
import time
import rocketreach
import oneaudit.modules


class OSINTLinkedInProgramData:
    def __init__(self, args):
        oneaudit.modules.args_parse_api_config(self, args)
        self.company_name = args.company_domain
        self.output_file = args.output


def parse_args(parser: argparse.ArgumentParser, module_parser: argparse.ArgumentParser):
    submodule_parser = module_parser.add_subparsers(dest='action', description='Target platform')

    # LinkedIn
    linkedin_module = submodule_parser.add_parser('linkedin', description='Scrap LinkedIn to fetch user profiles.')
    linkedin_module.add_argument('-d', '--domain', dest='company_domain', help='For example, "example.com".')
    linkedin_module.add_argument('-o', '--output', metavar='output.json', dest='output', help='Export results as JSON.', required=True)
    oneaudit.modules.args_api_config(linkedin_module)

    return parser.parse_args()


def _rocketreach_fetch_records(args: OSINTLinkedInProgramData):
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
            data = oneaudit.modules.get_cached_result(cached_result_key)
            if data is None:
                s = s.params(start=page * 100 + 1, size=100)
                result = s.execute()
                if result.is_success:
                    data = result.response.json()
                    oneaudit.modules.set_cached_result(cached_result_key, data)
                else:
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


def run(parser, module_parser):
    args = parse_args(parser, module_parser)
    if args.action == 'linkedin':
        args = OSINTLinkedInProgramData(args)

        results = []
        results.append(_rocketreach_fetch_records(args))

        with open(args.output_file, 'w') as output_file:
            json.dump({
                "version": 1.0,
                "entries": results,
            }, output_file, indent=4)
