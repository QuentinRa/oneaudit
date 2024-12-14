from oneaudit.api.leaks import LeaksAPICapability, BreachData
from oneaudit.api.leaks.provider import OneAuditLeaksAPIBulkProvider


# https://haveibeenpwned.com/API/v3#AllBreaches
class HaveIBeenPwnedFree(OneAuditLeaksAPIBulkProvider):
    def _init_capabilities(self, api_key, api_keys):
        return [LeaksAPICapability.INVESTIGATE_BULK, LeaksAPICapability.INVESTIGATE_BREACH] if api_key is not None else []

    def get_request_rate(self):
        return 2

    def __init__(self, api_keys):
        super().__init__(
            api_name='haveibeenpwned',
            request_args={
                'method': 'GET',
                'url': 'https://haveibeenpwned.com/api/v3/breaches',
            },
            api_keys=api_keys
        )

    def investigate_bulk(self, _):
        # We don't have anything to do without caching
        if self.only_use_cache:
            return True, {}

        cached, results = self.fetch_results_using_cache("breaches", default=[])
        indexed_data = {}
        for result in results:
            domain = result['Domain'].lower().strip()
            if not domain:
                domain = result['Name'].lower().strip()

            if domain not in indexed_data:
                indexed_data[domain] = []
            indexed_data[domain].append({
                'domain': domain,
                'title': result['Title'].lower().strip(),
                'name': result['Name'].lower().strip(),
                'date': result['BreachDate'],
                'scope': result['PwnCount'],
                'description': result['Description'].split("The data was provided")[0].strip(),
            })

        self._cache_indexed_data_if_required("breach_data_{key}", indexed_data)

        yield cached, {}

    def investigate_breach_from_name(self, breach):
        # We don't fetch new results
        self.only_use_cache = True

        _, data = self.fetch_results_using_cache(f"breach_data_{breach.source.split(' ')[0]}", default=None)

        breach_data = None
        if data:
            target_date = breach.date

            # Only one breach, use it
            if len(data['result']) == 1:
                breach_data = data['result'][0]
                if target_date < breach_data['date'][:7]:
                    breach_data['date'] = target_date

            else:
                # Look for the best breach to use
                for breach_candidate in data['result']:
                    current_breach_date = breach_candidate['date'][:7]
                    if current_breach_date == target_date:
                        breach_data = breach_candidate
                        break

                    # Is it the same year
                    if current_breach_date[:4] == target_date[:4]:
                        # NotImplementedError
                        if breach_data:
                            self.logger.error("Two breaches the same year, how do you determine the one to use?")
                            self.logger.error(f"Found: {breach_data}")
                            self.logger.error(f"Found: {breach_candidate}")
                            return True, None

                        breach_data = breach_candidate

        if not breach_data:
            self.logger.warning(f"No details found for {breach.source}.")
            return True, None

        yield True, {
            'breaches': [
                BreachData(
                    breach_data['name'],
                    breach_data['date'],
                    breach_data['description'],
                )
            ]
        }
