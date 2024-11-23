import oneaudit.api

class OSINTProviderManager(oneaudit.api.DefaultProviderManager):
    def __init__(self, api_keys):
        import rocketreach
        super().__init__([
            oneaudit.api.osint.rocketreach.RocketReachAPI(api_keys)
        ])

    def parse_records(self, args, input_file):
        result = []

        for provider in self.providers:
            result.append(provider.parse_records())

        return [v for k, v in result.items()]

class OSINTProvider(oneaudit.api.DefaultProvider):
    pass