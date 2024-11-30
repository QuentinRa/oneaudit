from oneaudit.api.manager import OneAuditBaseAPIManager
from oneaudit.api.osint.dns import DNSCapability


class OneAuditDNSAPIManager(OneAuditBaseAPIManager):
    """
    APIs related to emails
    """
    def __init__(self, api_keys):
        from oneaudit.api.osint.dns import virustotal
        super().__init__([
            # FREE
            # FREEMIUM
            virustotal.VirusTotalAPI(api_keys)
            # PAID
        ])

    def dump_subdomains(self, domain):
        """
        Indicates for each email if the email is verified or not.
        """
        results = {
            'subdomains': [],
        }
        _, results = self._call_all_providers_dict(
            heading="Investigate subdomains",
            capability=DNSCapability.SUBDOMAINS_ENUMERATION,
            stop_when_modified=False,
            method_name='dump_subdomains_from_domain',
            result=results,
            args=(domain,)
        )
        return sorted(set(results['subdomains']))
