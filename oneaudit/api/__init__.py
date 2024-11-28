class APIRateLimitException(Exception):
    pass


class FakeResponse:
    def __init__(self, status_code, response_data):
        self.status_code = status_code
        self._response_data = response_data

    def json(self):
        return self._response_data
