from oneaudit.api.socosint import SocialNetworkEnum, UserProfileRawData, UserProfileData
from oneaudit.api.socosint.linkedin.provider import OneAuditLinkedInAPIProvider
from oneaudit.api.socosint.linkedin import LinkedInAPICapability
from oneaudit.api.utils.caching import get_cached_result, set_cached_result
from rocketreach import Gateway, GatewayConfig
from oneaudit.api.osint import VerifiableEmail
from string import digits, ascii_letters
from requests import get, post
from secrets import choice
from random import randint
from time import sleep
from json import load

class RocketReachAPI(OneAuditLinkedInAPIProvider):
    def _init_capabilities(self, api_key, api_keys):
        return [
            LinkedInAPICapability.SEARCH_EMPLOYEES_BY_DOMAIN,
            LinkedInAPICapability.EXPORT_PROFILE_LIST,
            LinkedInAPICapability.PARSE_EXPORTED_PROFILE_LIST,
        ] if api_key is not None else []

    def handle_request(self, method):
        # RocketReach uses a handler to wrap the "requests" API
        return getattr(self.current_handler, method)().response

    def get_request_rate(self):
        return 5

    def handle_rate_limit(self, response):
        """API v2 returns retry-after. For v1, you are expected to handle it yourself."""
        wait = int(response.headers["retry-after"] if "retry-after" in response.headers else 0)
        if wait > 0:
            self.logger.warning(f"Rate-limited. Waiting for {wait} seconds.")
            sleep(wait)

    def __init__(self, api_keys):
        super().__init__(
            api_name='rocketreach',
            request_args={},
            api_keys=api_keys
        )

        # Requests are made using a wrapper
        self.handler = Gateway(GatewayConfig(self.api_key))
        self.current_handler = None

        # Load the session id if any
        self.session_id = api_keys.get('rocketreach_session')
        self.session_id = self.session_id if self.session_id and len(self.session_id) > 0 else None

        # Emails may have a status among these
        self.email_verified_mapper = {
            "accept_all": False,
            "unknown": False,
            "catch-all": False,
            "invalid": False,
            "valid": True
        }

    def search_employees_from_company_domain(self, company_domain, target_profile_list_id=None):
        search_handler = self.handler.person.search().filter(current_employer=f'\"{company_domain}\"')
        search_handler = search_handler.options(order_by="score")
        page = 0
        total = -1
        try:
            ids = []
            while True:
                targets = []
                self.logger.info(f"Querying page {page + 1}/{total if total != -1 else '?'}")
                self.current_handler = search_handler.params(start=page * 100 + 1, size=100)
                cached, data = self.fetch_results_using_cache(f"{company_domain}_score_{page}", default=None, method='execute')
                for profile in data["profiles"]:
                    target_emails = profile["teaser"]["emails"] + profile["teaser"]["professional_emails"]
                    target_emails = list(set(target_emails))
                    if not profile["name"]:
                        self.logger.warning(f"We found an employee with a blank name. We will skip it for now.")
                        continue
                    if not profile['links'] and 'linkedin_url' in profile:
                        profile['links'] = {SocialNetworkEnum.LINKEDIN.value: profile['linkedin_url']}
                    targets.append(UserProfileRawData(
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

            self._add_to_profile_list(target_profile_list_id, ids)
        except Exception as e:
            self.logger.error(f"Error received: {e}")

    def _add_to_profile_list(self, target_profile_list_id, ids):
        """
        Add profiles (from their IDs) to the target_profile_list.
        Use a long delay between requests.
        """
        ids_checked = get_cached_result(self.api_name, 'ids_checked', do_not_expire=True)
        if ids_checked is None:
            ids_checked = []
        ids_to_check = [value for value in ids if value not in ids_checked]
        if not ids_to_check:
            return

        self.logger.warning(f"You have to manually fetch {len(ids_to_check)} records.")

        # We can try to fetch the trigger the requests for you, but it's somewhat dirty
        if not self.session_id or not target_profile_list_id:
            return

        kill_switch = 0
        csrf_token = ''.join(choice(ascii_letters + digits) for _ in range(32))
        i = 0
        while i < len(ids_to_check):
            self.logger.info(f'Fetching batch from {i} to {i + 25}')
            batch = ids_to_check[i:i + 25]
            response = post(
                url=f'https://rocketreach.co/v1/profileList/{target_profile_list_id}/lookup',
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
                if kill_switch >= 2:
                    wait = randint(1200, 1800)
                    self.logger.warning(f"Hit a hard rate-limit, waiting {wait} seconds.")
                    sleep(wait)
                    kill_switch += 1
                    continue

                self.logger.info(f"Rate-limited. Waiting five minutes.")
                kill_switch += 1
                sleep(300)
                continue

            # Save the status
            ids_checked.extend(batch)
            set_cached_result(self.api_name, 'ids_checked', ids_checked)

            # Waiting time
            wait = randint(60, 120)
            self.logger.info(f"Waiting {wait} seconds to respect fair use.")
            sleep(wait)

            i += 25
            kill_switch = 0

    def export_profiles_from_profile_list(self, target_profile_list_id):
        if not self.session_id:
            raise Exception(f"{self.api_name}: add a valid 'rocketreach_session' in your configuration file.")

        # Get Account ID
        self.current_handler = self.handler.account
        _, data = self.fetch_results_using_cache(f'{self.api_name}_profile_id', default=None, method='get')
        account_id = data['id']

        # Get Count
        headers = {
            'Cookie': f'sessionid-20191028={self.session_id}; selected_profile_list_id_{account_id}={target_profile_list_id}',
            'User-Agent': self.request_args["headers"]['User-Agent'],
        }
        response = get(
            f'https://rocketreach.co/v1/profileList/{target_profile_list_id}/profiles?page=1&order_by=-create_time&limit=1',
            headers=headers
        )
        if not self.is_response_valid(response):
            raise Exception(f"{self.api_name} cannot handle a rate-limit inside self.export_records_from_profile")
        response_count = response.json()['count']

        cached_response = get_cached_result(self.api_name, f'export_profile_{target_profile_list_id}', do_not_expire=True)
        result = {
            'count': cached_response['count'] if cached_response else 0,
            'entries': cached_response['entries'] if cached_response else []
        }
        page = 1
        missing_entries = response_count - result['count']
        while missing_entries > 0:
            self.logger.debug(f"Missing {missing_entries} entries from profile={target_profile_list_id}")

            limit = 100 if missing_entries > 100 else missing_entries
            response = get(
                url=f'https://rocketreach.co/v1/profileList/{target_profile_list_id}/profiles?page={page}&order_by=-create_time&limit={limit}',
                headers=headers
            )

            if not self.is_response_valid(response):
                raise Exception(f"{self.api_name} cannot handle a rate-limit inside self.export_records_from_profile")

            data = response.json()
            result['entries'].extend(data['records'])
            result['count'] += len(data['records'])
            set_cached_result(self.api_name, f'export_profile_{target_profile_list_id}', result)

            self.logger.info(f"Waiting 30 seconds to respect fair use.")
            sleep(30)

            if data['num_pages'] == page:
                break

            page += 1
            missing_entries = response_count - result['count']

        self.logger.info("Export done.")
        return result['entries']

    def parse_records_from_export(self, employee_filters, input_file):
        targets = []
        file_contents = load(input_file)
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
                    emails.append(VerifiableEmail(
                        email['email'].lower(),
                        self.email_verified_mapper[email['validity']]
                    ))

                should_skip = True
                for employee_filter in employee_filters:
                    if employee_filter in entry["current_employer"].lower():
                        should_skip = False
                        break
                if should_skip:
                    # If the employee is not part of the target company
                    all_employers.add(entry["current_employer"].lower())
                    continue

                targets.append(UserProfileData(
                    entry["first_name"],
                    entry["last_name"],
                    list(set(emails)),
                    {SocialNetworkEnum.get(k): str(v) for k, v in (entry['links'] if entry['links'] else {}).items()}
                ))

        self.logger.debug(f"All employers that were not allowed due to filtering: {all_employers}")
        return targets