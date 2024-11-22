from oneaudit.api.leaks import LeaksProvider

# https://docs.whiteintel.io/whiteintel-api-doc
class WhiteIntelAPI(LeaksProvider):
    def __init__(self, _):
        super().__init__(
            unique_identifier='whiteintel_regular_',
            request_args={
                'method': 'POST',
                'json': {}
            }
        )

    def fetch_domain_results(self, domain):
        print("Hello, World!")
        return True, {}

    def handle_rate_limit(self, response):
        pass

    def get_rate(self):
        return 1