from oneaudit.api.manager import OneAuditBaseAPIManager
from oneaudit.api.osint.dns import DNSCapability


class OneAuditDNSAPIManager(OneAuditBaseAPIManager):
    """
    APIs related to emails
    """
    def __init__(self, api_keys):
        from oneaudit.api.osint.dns import virustotal, subfinder, crtsh
        super().__init__([
            # FREE
            subfinder.SubFinderAPI(api_keys),
            crtsh.CrtShAPI(api_keys),
            # FREEMIUM
            virustotal.VirusTotalAPI(api_keys)
            # PAID
        ])

    def dump_subdomains(self, domain):
        """
        Indicates for each email if the email is verified or not.
        """
        _, extra = self._call_all_providers_dict(
            heading="Investigate wildcard subdomains",
            capability=DNSCapability.FETCH_WILDCARD_DOMAINS,
            stop_when_modified=False,
            method_name='dump_wildcard_domains_from_domain',
            result={
                'wildcard': []
            },
            args=(domain,)
        )

        results = { 'subdomains': [], }
        for domain in set([domain] + extra['wildcard']):
            _, results = self._call_all_providers_dict(
                heading="Investigate subdomains",
                capability=DNSCapability.SUBDOMAINS_ENUMERATION,
                stop_when_modified=False,
                method_name='dump_subdomains_from_domain',
                result=results,
                args=(domain,)
            )

        final_results = {}
        for result in results['subdomains']:
            # Add the domain, since we only have this one
            if result.domain_name not in final_results:
                final_results[result.domain_name] = [result]
                continue

            # If we already have one result that may have an IP
            if not result.ip_address:
                continue

            old_result = final_results[result.domain_name][0]

            # Discard if there is no IP address
            if not old_result.ip_address:
                final_results[result.domain_name] = [result]
            else:
                final_results[result.domain_name].append(result)

        return sorted(set([e for v in final_results.values() for e in v]))
