from oneaudit.api.osint import OSINTProvider, OSINTScrappedDataFormat, OSINTScrappedEmailDataFormat, SocialNetworkEnum
from oneaudit.api import get_cached_result, set_cached_result
import json
import time
import string
import random
import secrets
import requests
import rocketreach


class RocketReachAPI(OSINTProvider):
    def __init__(self, api_keys, cache_only):
        super().__init__(
            api_name='rocketreach',
            request_args={},
            api_keys=api_keys,
            show_notice=False
        )
        if not cache_only:
            self.handler = rocketreach.Gateway(rocketreach.GatewayConfig(self.api_key))
            self.current_handler = None
            self.show_notice()

            # Undocumented
            rocketreach_session = api_keys.get('rocketreach_session', {})
            self.session_id = rocketreach_session.get("session_id", None)
            self.profile_list_id = rocketreach_session.get("profile_list_id", None)

        self.email_verified_mapper = {
            "accept_all": False,
            "unknown": False,
            "catch-all": False,
            "invalid": False,
            "valid": True
        }


    def fetch_targets_for_company(self, company_name):
        search_handler = self.handler.person.search().filter(current_employer=f'\"{company_name}\"')
        page = 0
        total = -1
        try:
            ids = []
            while True:
                targets = []
                self.logger.info(f"{self.api_name}: Querying page {page + 1}/{total if total != -1 else "?"}")
                self.current_handler = search_handler.params(start=page * 100 + 1, size=100)
                cached, data = self.fetch_results_using_cache(f"{company_name}_{page}", method='execute')
                for profile in data["profiles"]:
                    target_emails = profile["teaser"]["emails"] + profile["teaser"]["professional_emails"]
                    target_emails = list(set(target_emails))
                    targets.append(OSINTScrappedDataFormat(
                        profile["name"],
                        profile['birth_year'],
                        len(target_emails),
                        {SocialNetworkEnum.get(k): str(v) for k, v in (profile['links'] if profile['links'] else {}).items()}
                    ))
                    if profile['status'] != "complete":
                        ids.append(profile['id'])

                yield cached, { self.api_name: targets }

                pagination = data['pagination']
                if pagination['next'] > pagination['total']:
                    break
                page += 1
                total = (pagination['total'] // 100) + 1

            ids_checked = get_cached_result(self.api_name, 'ids_checked', do_not_expire=True)
            if ids_checked is None:
                ids_checked = []
            ids_to_check = [value for value in ids if value not in ids_checked]
            if ids_to_check:
                self.logger.warning(f"{self.api_name}: You have to manually fetch {len(ids_to_check)} records.")

                # We can try to fetch the trigger the requests for you, but it's somewhat dirty
                if self.session_id and self.profile_list_id:
                    csrf_token = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(32))
                    for i in range(0, len(ids_to_check), 25):
                        self.logger.info(f'{self.api_name}: Fetching batch from {i} to {i + 25}')
                        batch = ids_to_check[i:i + 25]
                        response = requests.post(
                            url=f'https://rocketreach.co/v1/profileList/{self.profile_list_id}/lookup',
                            headers={
                                'Cookie': f'sessionid-20191028={self.session_id}; validation_token={csrf_token}',
                                'User-Agent': self.request_args["headers"]['User-Agent'],
                                "X-CSRFToken": csrf_token,
                                'referer': 'https://rocketreach.co/person'
                            },
                            json={
                                "profile_ids": batch,
                                "linkedin_urls": [],
                            }
                        )

                        # Check the reply
                        if not self.is_response_valid(response):
                            self.logger.info(f"{self.api_name}: Rate-limited. Waiting a minute.")
                            time.sleep(60)
                            continue

                        # Save the status
                        ids_checked.extend(batch)
                        set_cached_result(self.api_name, 'ids_checked', ids_checked)

                        # Waiting time
                        wait = random.randint(30, 60)
                        self.logger.info(f"{self.api_name}: waiting {wait} seconds to respect fair use.")
                        time.sleep(wait)
        except Exception as e:
            self.logger.error(f"{self.api_name}: Error received: {e}")

    def handle_request(self, method):
        return getattr(self.current_handler, method)().response

    def parse_records_from_file(self, file_source, employee_filter, input_file):
        targets = []
        if file_source != 'rocketreach':
            return targets
        file_contents = json.load(input_file)
        if not isinstance(file_contents, list):
            file_contents = [file_contents]

        all_employers = set()
        for file_content in file_contents:
            for entry in file_content["entries"]:
                emails = []
                for email in entry['emails']:
                    if email['source'] == "predicted":
                        if email['format_probability'] and email['format_probability'] < 35:
                            continue
                        if email['confidence'] < 50:
                            continue
                    emails.append(OSINTScrappedEmailDataFormat(
                        email['email'].lower(),
                        self.email_verified_mapper[email['validity']]
                    ))

                # If the employee is not part of the target company
                all_employers.add(entry["current_employer"].lower())
                if employee_filter not in entry["current_employer"].lower():
                    continue

                targets.append({
                    "first_name": entry["first_name"],
                    "last_name": entry["last_name"],
                    'emails': emails,
                    'links': {SocialNetworkEnum.get(k): str(v) for k, v in (entry['links'] if entry['links'] else {}).items()}
                })

        self.logger.debug(f"All employers: {all_employers}")
        return targets

    def export_records_from_profile(self, source, profile_list_id):
        if source != "rocketreach":
            return []

        if not self.session_id:
            raise Exception(f"{self.api_name}: missing undocumented parameter, check the code.")

        # Get Account ID
        self.current_handler = self.handler.account
        _, data = self.fetch_results_using_cache(f'{self.api_name}_profile_id', method='get')
        account_id = data['id']

        # Get Count
        headers = {
            'Cookie': f'sessionid-20191028={self.session_id}; selected_profile_list_id_{account_id}={profile_list_id}',
            'User-Agent': self.request_args["headers"]['User-Agent'],
        }
        response = requests.get(
            f'https://rocketreach.co/v1/profileList/{profile_list_id}/profiles?page=1&order_by=-create_time&limit=1',
            headers=headers
        )
        if not self.is_response_valid(response):
            raise Exception(f"{self.api_name} cannot handle a rate-limit inside self.export_records_from_profile")
        response_count = response.json()['count']

        cached_response = get_cached_result(self.api_name, f'export_profile_{profile_list_id}', do_not_expire=True)
        result = {
            'count': cached_response['count'] if cached_response else 0,
            'entries': cached_response['entries'] if cached_response else []
        }
        page = 1
        missing_entries = response_count - result['count']
        while missing_entries > 0:
            self.logger.debug(f"{self.api_name}: Missing {missing_entries} entries from profile={profile_list_id}")

            limit = 100 if missing_entries > 100 else missing_entries
            response = requests.get(
                url=f'https://rocketreach.co/v1/profileList/{profile_list_id}/profiles?page={page}&order_by=-create_time&limit={limit}',
                headers=headers
            )

            if not self.is_response_valid(response):
                raise Exception(f"{self.api_name} cannot handle a rate-limit inside self.export_records_from_profile")

            data = response.json()
            result['entries'].extend(data['records'])
            result['count'] += len(data['records'])
            set_cached_result(self.api_name, f'export_profile_{profile_list_id}', result)

            self.logger.info(f"{self.api_name}: waiting 30 seconds to respect fair use.")
            time.sleep(30)

            if data['num_pages'] == page:
                break

            page += 1
            missing_entries = response_count - result['count']

        return result['entries']

    def handle_rate_limit(self, response):
        wait = int(response.headers["retry-after"] if "retry-after" in response.headers else 2)
        self.logger.warning(f"{self.api_name}: Rate-limited. Waiting for {wait} seconds.")
        time.sleep(wait)

    def get_rate(self):
        return 5
