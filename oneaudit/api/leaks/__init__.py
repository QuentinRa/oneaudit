class LeaksProviderManager:
    providers = [

    ]

    def get_base_data(self):
        return {
            'passwords': [],
            'censored': [],
            'hashes': [],
            'info_stealers': [],
        }

    def append_data(self, email, current):
        result = {
            'passwords': current['passwords'],
            'censored': current['censored'],
            'hashes': current['hashes'],
            'info_stealers': current['info_stealers'],
        }

        for provider in self.providers:
            print(email)
            for k, v in {}:
                result[k] = v

        return result
