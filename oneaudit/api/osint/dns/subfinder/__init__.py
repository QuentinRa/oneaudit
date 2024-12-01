from oneaudit.api.osint.dns import DNSCapability, DomainInformation
from oneaudit.api.osint.dns.provider import OneAuditDNSAPIProvider
from oneaudit.api.utils.caching import set_cached_result, get_cached_result
from oneaudit.utils.io import to_absolute_path
from subprocess import run
from json import loads


# https://github.com/projectdiscovery/subfinder
class SubFinderAPI(OneAuditDNSAPIProvider):
    def _init_capabilities(self, api_key, api_keys):
        return [DNSCapability.SUBDOMAINS_ENUMERATION] if api_key is not None else []

    def __init__(self, api_keys):
        super().__init__(
            api_name='subfinder',
            request_args={},
            api_keys=api_keys
        )
        # Either it's a path or a
        self.executable = to_absolute_path(self.api_key) if self.api_key and '/' in self.api_key else self.api_key

    def dump_subdomains_from_domain(self, domain):
        cached_result_key = f"subfinder_{domain}"
        data = get_cached_result(self.api_name, cached_result_key)
        if not data:
            # Execute the given executable with the given parameters
            # User can set both the executable path and the parameter, and we won't control it
            result = run([self.executable] + ["-d", domain, "-oJ", "-silent", "-duc", "-recursive"], capture_output=True, text=True)
            if result.returncode != 0 or result.stderr.strip():
                raise Exception(f"{self.api_name}: failed to execute {self.executable}.\nError: {result.stderr}")
            data = {
                'stdout': result.stdout
            }
            set_cached_result(self.api_name, f"subfinder_{domain}", data)

        data = loads('[' + ','.join([line.strip() for line in data['stdout'].split() if line]) + ']')
        yield True, {
            # Subfinder is bad+slow at resolving IPs, so we simply don't (for now)
            'subdomains': [DomainInformation(entry['host'], None) for entry in data]
        }
        yield True, {}
