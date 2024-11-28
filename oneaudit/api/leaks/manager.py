from oneaudit.api.manager import OneAuditBaseAPIManager
from oneaudit.api.leaks import LeaksAPICapability
from oneaudit.api.leaks import aura, hashmob


# from oneaudit.api.leaks import aura, hashmob, hudsonrocks, leakcheck
# from oneaudit.api.leaks import nth, proxynova, snusbase, spycloud
# from oneaudit.api.leaks import whiteintel

class OneAuditLeaksAPIManager(OneAuditBaseAPIManager):
    """
    APIs related to leaks
    """
    def __init__(self, api_keys):
        super().__init__([
            # FREE
            aura.AuraAPI(api_keys),
            # nth.NameThatHashAPI(api_keys),
            # proxynova.ProxyNovaAPI(api_keys),
            # FREEMIUM
            # hudsonrocks.HudsonRocksAPI(api_keys),
            hashmob.HashMobAPI(api_keys),
            # spycloud.SpyCloudAPI(api_keys),
            # whiteintel.WhiteIntelAPI(api_keys),
            # PAID
            # leakcheck.LeakCheckAPI(api_keys),
            # snusbase.SnusbaseAPI(api_keys),
        ])

    def investigate_leaks(self, credentials):
        results = {}

        for credential in credentials:
            key = credential['login']
            if key in results:
                print(key)
                continue

            results[key] = {
                'logins': [],
                'passwords': [],
                'censored_logins': [],
                'censored_passwords': [],
                'raw_hashes': [],
                'info_stealers': [],
                'breaches': [],
                'verified': False,
            }

            # Get the leaks per email, and save them in the record associated with the login
            for email in credential['emails']:
                was_modified, results[key] = self._call_all_providers_dict(
                    heading="Investigate leaks",
                    capability=LeaksAPICapability.INVESTIGATE_LEAKS_BY_EMAIL,
                    stop_when_modified=False,
                    method_name='investigate_leaks_by_email',
                    result=results[key],
                    args=(email,)
                )
                if was_modified and email == key:
                    credential['verified'] = True
                    self.logger.debug(f"Email {email} was verified due to leaks associated to it.")

            # fixme: handle new logins

            # Use the value in credential that may have been updated
            results[key]['verified'] = credential['verified']

            # fixme: attempt to crack hashes

            # fixme: sort

        return [{"login": key, **value} for key, value in results.items()]

    def investigate_domain(self, domain):
        if not domain:
            return []
        print(domain)
        return []