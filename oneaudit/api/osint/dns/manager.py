from oneaudit.api.manager import OneAuditBaseAPIManager
from oneaudit.api.osint.dns import DNSCapability, DomainInformation


class OneAuditDNSAPIManager(OneAuditBaseAPIManager):
    """
    APIs related to DNS records and IPs
    """
    def __init__(self, api_keys):
        from oneaudit.api.osint.dns import virustotal, subfinder, crtsh
        from oneaudit.api.osint.dns import whiteintel, certspotter, webarchive
        from oneaudit.api.osint.dns import ipwhois
        super().__init__([
            # FREE
            subfinder.SubFinderAPI(api_keys),
            crtsh.CrtShAPI(api_keys),
            certspotter.CertSpotterAPI(api_keys),
            webarchive.WebArchiveAPI(api_keys),
            # FREEMIUM
            ipwhois.IPWhoisAPI(api_keys),
            virustotal.VirusTotalAPI(api_keys),
            whiteintel.WhiteIntelAPI(api_keys),
            # PAID
        ])

    def dump_subdomains(self, domain):
        """
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

        cleaned_results = {}
        for result in results['subdomains']:
            domain_name = result.domain_name.split("@")[-1]
            if domain_name != result.domain_name:
                result = DomainInformation(domain_name, result.ip_address, result.asn)

            # Add the domain, since we only have this one
            if result.domain_name not in cleaned_results:
                cleaned_results[result.domain_name] = [result]
                continue

            # If we already have one result that may have an IP
            if not result.ip_address:
                continue

            old_result = cleaned_results[result.domain_name][0]

            # Discard if there is no IP address
            if not old_result.ip_address:
                cleaned_results[result.domain_name] = [result]
            else:
                cleaned_results[result.domain_name].append(result)

        cleaned_results = sorted(set([e for v in cleaned_results.values() for e in v]))
        final_results = []
        for result in cleaned_results:
            asn = None
            if result.ip_address:
                for _, api_result in self._call_all_providers(
                        heading="Investigate ASN for IP",
                        capability=DNSCapability.ASN_INVESTIGATION,
                        method_name='find_asn_data_for_ip',
                        args=(result.ip_address,)):
                    asn = api_result
                    if asn is not None:
                        break

            final_results.append(
                DomainInformation(
                    result.domain_name,
                    result.ip_address,
                    asn,
                )
            )

        return final_results
