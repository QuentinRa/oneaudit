from oneaudit.api.socosint import SocialNetworkEnum, UserProfileRawData
from oneaudit.api.socosint.linkedin.provider import OneAuditLinkedInAPIProvider
from oneaudit.api.socosint.linkedin import LinkedInAPICapability
from oneaudit.api.utils.caching import get_cached_result, set_cached_result
from rocketreach import Gateway, GatewayConfig
from string import digits, ascii_letters
from requests import post
from secrets import choice
from random import randint
from time import sleep

class RocketReachAPI(OneAuditLinkedInAPIProvider):
    def _init_capabilities(self, api_key, api_keys):
        return [
            LinkedInAPICapability.SEARCH_EMPLOYEES_BY_DOMAIN,
            LinkedInAPICapability.EXPORT_PROFILE_LIST,
            LinkedInAPICapability.PARSE_EXPORTED_PROFILE_LIST,
        ] if api_key is not None else [LinkedInAPICapability.PARSE_EXPORTED_PROFILE_LIST]

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
                self.logger.info(f"{self.api_name}: Querying page {page + 1}/{total if total != -1 else "?"}")
                self.current_handler = search_handler.params(start=page * 100 + 1, size=100)
                cached, data = self.fetch_results_using_cache(f"{company_domain}_score_{page}", method='execute')
                for profile in data["profiles"]:
                    target_emails = profile["teaser"]["emails"] + profile["teaser"]["professional_emails"]
                    target_emails = list(set(target_emails))
                    if not profile["name"]:
                        self.logger.warning(f"{self.api_name}: we found an employee with a blank name. We will skip it for now.")
                        continue
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
            self.logger.error(f"{self.api_name}: Error received: {e}")

    def _add_to_profile_list(self, target_profile_list_id, ids):
        ids_checked = get_cached_result(self.api_name, 'ids_checked', do_not_expire=True)
        if ids_checked is None:
            ids_checked = []
        ids_to_check = [value for value in ids if value not in ids_checked]
        if ids_to_check:
            self.logger.warning(f"{self.api_name}: You have to manually fetch {len(ids_to_check)} records.")

            # We can try to fetch the trigger the requests for you, but it's somewhat dirty
            if self.session_id and target_profile_list_id:
                kill_switch = 0
                csrf_token = ''.join(choice(ascii_letters + digits) for _ in range(32))
                i = 0
                while i < len(ids_to_check):
                    self.logger.info(f'{self.api_name}: Fetching batch from {i} to {i + 25}')
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
                            self.logger.warning(f"{self.api_name}: hit a hard rate-limit, waiting {wait} seconds.")
                            sleep(wait)
                            kill_switch += 1
                            continue

                        self.logger.info(f"{self.api_name}: Rate-limited. Waiting five minutes.")
                        kill_switch += 1
                        sleep(300)
                        continue

                    # Save the status
                    ids_checked.extend(batch)
                    set_cached_result(self.api_name, 'ids_checked', ids_checked)

                    # Waiting time
                    wait = randint(60, 120)
                    self.logger.info(f"{self.api_name}: waiting {wait} seconds to respect fair use.")
                    sleep(wait)

                    i += 25
                    kill_switch = 0

    def get_request_rate(self):
        return 5
