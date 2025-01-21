from oneaudit.api.osint.hosts import HostScanningAPICapability
from oneaudit.api.osint.hosts.provider import OneAuditPortScanningAPIProvider


# https://docs.leakix.net/docs/api/
class LeakIXAPI(OneAuditPortScanningAPIProvider):
    def _init_capabilities(self, api_key, api_keys):
        return [HostScanningAPICapability.HOST_SCANNING] if api_key is not None else []

    def get_request_rate(self):
        return 1.1

    def __init__(self, api_keys):
        super().__init__(
            api_name='leakix',
            request_args={
                'method': 'GET',
                'headers': {
                    'accept': 'application/json'
                }
            },
            api_keys=api_keys
        )
        self.request_args['headers']['api-key'] = self.api_key
        self.api_endpoint = 'https://leakix.net/host/{ip_address}'
        self.known_events = [
            'HttpPlugin', 'SshRegresshionPlugin', 'SSHOpenPlugin', 'GitConfigHttpPlugin'
        ]

    def assert_is_known_event(self, event_source, source):
        if event_source not in self.known_events:
            self.logger.warning(f"Investigate new event: {event_source}: {source}")

            # Trigger warnings once
            self.known_events.append(event_source)

    def investigate_host_by_ip(self, ip_address):
        self.request_args['url'] = self.api_endpoint.format(ip_address=ip_address)
        cached, result = self.fetch_results_using_cache(f"ip_{ip_address}", default={'Services': None})
        results = {'ports': [], 'stack': [], 'vulns': []}

        # service['protocol']
        for service in result['Services'] if result['Services'] else []:
            self.assert_is_known_event(service['event_source'], service)
            results['ports'].append(int(service['port']))

        for leak in result['Leaks'] if result['Leaks'] else []:
            results['ports'].extend([int(p) for p in leak['open_ports']])
            for event in leak['events']:
                self.assert_is_known_event(event['event_source'], event)

                if event['event_source'] == "GitConfigHttpPlugin":
                    results['vulns'].append('Found exposed GIT config.')

                soft = event['service']['software']
                if soft:
                    results['stack'].append(soft['name'] + (f":{soft['version']}" if soft['version'] else ""))

        yield cached, results
