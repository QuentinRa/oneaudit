from oneaudit.api.osint import OSINTProvider, OSINTScrappedDataFormat
import json
import time
import rocketreach


class RocketReachAPI(OSINTProvider):
    def __init__(self, api_keys):
        super().__init__(
            api_name='rocketreach',
            request_args={},
            api_keys=api_keys
        )
        self.handler = rocketreach.Gateway(rocketreach.GatewayConfig(self.api_key))
        self.search_handler = rocketreach.Gateway(rocketreach.GatewayConfig(self.api_key))

    def fetch_targets_for_company(self, company_name):
        search_handler = self.handler.person.search().filter(current_employer=f'\"{company_name}\"')
        page = 0
        total = -1
        try:
            while True:
                targets = []
                self.logger.info(f"{self.api_name}: Querying page {page + 1}/{total if total != -1 else "?"}")
                self.search_handler = search_handler.params(start=page * 100 + 1, size=100)
                cached, data = self.fetch_results_using_cache(f"{company_name}_{page}")
                for profile in data["profiles"]:
                    target_emails = profile["teaser"]["emails"] + profile["teaser"]["professional_emails"]
                    target_emails = list(set(target_emails))
                    targets.append(OSINTScrappedDataFormat(
                        profile["name"],
                        profile["linkedin_url"],
                        profile['birth_year'],
                        len(target_emails),
                    ))

                yield cached, { self.api_name: targets }

                pagination = data['pagination']
                if pagination['next'] > pagination['total']:
                    break
                page += 1
                total = (pagination['total'] // 100) + 1
        except Exception as e:
            self.logger.error(f"{self.api_name}: Error received: {e}")

    def handle_request(self):
        return self.search_handler.execute().response

    def parse_records_from_file(self, file_source, input_file):
        targets = []
        if file_source != 'rocketreach':
            return targets
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

            targets.append({
                "first_name": entry["first_name"],
                "last_name": entry["last_name"],
                "linkedin_url": entry["linkedin_url"],
                'emails': emails,
            })
        return targets

    def handle_rate_limit(self, response):
        wait = int(response.headers["retry-after"] if "retry-after" in response.headers else 2)
        self.logger.warning(f"{self.api_name}: Rate-limited. Waiting for {wait} seconds.")
        time.sleep(wait)

    def get_rate(self):
        return 5
