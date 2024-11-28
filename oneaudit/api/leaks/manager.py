from oneaudit.api.leaks import aura, hashmob, hudsonrocks, leakcheck
from oneaudit.api.leaks import nth, proxynova, snusbase, spycloud
from oneaudit.api.leaks import whiteintel

class OneAuditLeaksAPIManager:
    """
    APIs related to leaks
    """
    def __init__(self, api_keys):
        super().__init__([
            # FREE
            aura.AuraAPI(api_keys),
            nth.NameThatHashAPI(api_keys),
            proxynova.ProxyNovaAPI(api_keys),
            # FREEMIUM
            hudsonrocks.HudsonRocksAPI(api_keys),
            hashmob.HashMobAPI(api_keys),
            spycloud.SpyCloudAPI(api_keys),
            whiteintel.WhiteIntelAPI(api_keys),
            # PAID
            leakcheck.LeakCheckAPI(api_keys),
            snusbase.SnusbaseAPI(api_keys),
        ])

    def investigate_leaks(self, credentials):
        print(credentials)

        return []

    def investigate_domain(self, domain):
        print(domain)

        return []