from oneaudit.api.provider import OneAuditBaseProvider


class OneAuditDNSAPIProvider(OneAuditBaseProvider):
    """
    Implementation of an API related to DNS.
    """
    def __init__(self, api_name, request_args, api_keys):
        super().__init__(api_name, request_args, api_keys)

    def dump_subdomains_from_domain(self, domain):
         yield True, {'subdomains': []}

    def dump_wildcard_domains_from_domain(self, domain):
        yield True, {'wildcard': []}
