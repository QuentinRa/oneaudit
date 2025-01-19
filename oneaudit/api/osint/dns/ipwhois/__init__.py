from oneaudit.api.osint.dns import DNSCapability, ASNInformation
from oneaudit.api.osint.dns.provider import OneAuditDNSAPIBulkProvider
from ipaddress import ip_network, ip_address as ip_address_object
from oneaudit.api.utils.caching import get_cached_result

# https://ipwhois.io/documentation
# https://api.bgpview.io/asn/199575
# https://api.bgpview.io/asn/199575/prefixes
class IPWhoisAPI(OneAuditDNSAPIBulkProvider):
    def get_request_rate(self):
        return 1

    def _init_capabilities(self, api_key, api_keys):
        return [DNSCapability.ASN_INVESTIGATION] if api_key is not None else []

    def __init__(self, api_keys):
        super().__init__(
            api_name='ipwhois',
            request_args={
                'method': 'GET'
            },
            api_keys=api_keys
        )
        self.api_endpoint = 'https://ipwho.is/{ip_address}'
        self.api_external_endpoint = 'https://api.bgpview.io/asn/{asn_id}/prefixes'

    def find_asn_data_for_ip(self, ip_address):
        cached = True
        entry_key = f'{self.api_name}_parsed_ip_{ip_address}'
        result = get_cached_result(self.api_name, entry_key, do_not_expire=True)
        if True:
            # Get the ASN Number
            self.request_args['url'] = self.api_endpoint.format(ip_address=ip_address)
            cached, result = self.fetch_results_using_cache(f"ip_{ip_address}", default=[])
            # Get the associated IP ranges
            if 'connection' in result and 'asn' in result['connection']:
                asn_id, asn_name = result['connection']['asn'], result['connection']['isp']
                self.request_args['url'] = self.api_external_endpoint.format(asn_id=asn_id)
                cached, result = self.fetch_results_using_cache(f"asn_{asn_id}", default=[])
                # Keep the results clean and tidy
                all_owned_ip_addresses_ranges = result['data']['ipv4_prefixes']
                should_cache_everything = len(all_owned_ip_addresses_ranges) < 10

                indexed_data = {}
                ip_address_obj = ip_address_object(ip_address)
                for ip_entry in all_owned_ip_addresses_ranges:
                    asn_ip_range = ip_entry['prefix']
                    asn_ip_range_expanded = ip_network(asn_ip_range)

                    if ip_address_obj not in asn_ip_range_expanded and not should_cache_everything:
                         continue

                    # Do not cache big networks
                    if asn_ip_range_expanded.num_addresses - 2 > 500:
                        asn_ip_range_expanded = [ip_address]

                    # Do not cache ISPs
                    if not should_cache_everything:
                        asn_ip_range_expanded = [ip_address]

                    for ip_in_range_expanded in asn_ip_range_expanded:
                        indexed_data[ip_in_range_expanded] = ASNInformation(
                            asn_id,
                            asn_name,
                            asn_ip_range
                        )

                self._cache_indexed_data_if_required("parsed_ip_{key}", indexed_data)
                result = get_cached_result(self.api_name, entry_key, do_not_expire=True)

        yield cached, result['result'] if result else None

