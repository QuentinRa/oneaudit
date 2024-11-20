from oneaudit.api.leaks import LeaksProvider

# https://cavalier.hudsonrock.com/docs
class HudsonRocksAPI(LeaksProvider):
    def fetch_results(self, email):
        return False, {}

    # Minimum rate is "0.2" for 5 requests/second
    def get_rate(self):
        return 0.5