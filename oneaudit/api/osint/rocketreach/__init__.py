from oneaudit.api.osint import OSINTProvider


class RocketReachAPI(OSINTProvider):
    def __init__(self, api_keys):
        super().__init__(
            api_name='rocketreach',
            unique_identifier='rocketreach_',
            request_args={},
            api_keys=api_keys
        )

    def handle_rate_limit(self, response):
        self.logger.error(response.text)
        self.logger.error(response.headers)
        pass

    def get_rate(self):
        return 5

# def _rocketreach_fetch_records(args: OSINTScrapLinkedInProgramData):
#     results = {
#         "source": "rocketreach",
#         "date": time.time(),
#         "version": 1.0,
#         "targets": []
#     }
#
#     api_key = args.api_keys.get("rocketreach", None)
#     if not api_key:
#         print("[!] RocketReach Skipped: API Key Missing.")
#         return results
#
#     rr = rocketreach.Gateway(rocketreach.GatewayConfig(api_key))
#     s = rr.person.search().filter(current_employer=f'\"{args.company_name}\"')
#
#     page = 0
#     try:
#         while True:
#             cached_result_key = "rocketreach_" + args.company_name + "_" + str(page)
#             data = oneaudit.api.get_cached_result("rocketreach", cached_result_key)
#             if data is None:
#                 s = s.params(start=page * 100 + 1, size=100)
#                 result = s.execute()
#                 if result.is_success:
#                     data = result.response.json()
#                     oneaudit.api.set_cached_result(cached_result_key, data)
#                 else:
#                     if result.response.status_code == 429:
#                         wait = int(result.response.headers["retry-after"] if "retry-after" in result.response.headers else 2)
#                         print(f"Waiting for {wait} seconds.")
#                         time.sleep(wait)
#                         continue
#                     print(result.response.status_code)
#                     print(result.response.headers)
#                     print(result.response.text)
#                     raise Exception(f'Error: {result.message}!', True)
#
#             for profile in data["profiles"]:
#                 target_emails = profile["teaser"]["emails"] + profile["teaser"]["professional_emails"]
#                 target_emails = list(set(target_emails))
#                 results["targets"].append({
#                     "full_name": profile["name"],
#                     "linkedin_url": profile["linkedin_url"],
#                     'birth_year': profile['birth_year'],
#                     '_status': profile['status'],
#                     '_count': len(target_emails),
#                 })
#
#             pagination = data['pagination']
#             if pagination['next'] > pagination['total']:
#                 break
#             page += 1
#     except Exception as e:
#         print(e)
#     return results
#
#
# def _rocketreach_parse_records(args, input_file):
#     results = {
#         "source": "rocketreach",
#         "date": time.time(),
#         "version": 1.0,
#         "targets": []
#     }
#
#     if args.file_source != 'rocketreach':
#         return results
#     entries = json.load(input_file)["records"]
#     for entry in entries:
#         emails = []
#         for email in entry['emails']:
#             if email['source'] == "predicted":
#                 if email['format_probability'] and email['format_probability'] < 35:
#                     continue
#                 if email['confidence'] < 50:
#                     continue
#             emails.append(email['email'].lower())
#
#         results["targets"].append({
#             "first_name": entry["first_name"],
#             "last_name": entry["last_name"],
#             "linkedin_url": entry["linkedin_url"],
#             'emails': emails,
#         })
#     return results