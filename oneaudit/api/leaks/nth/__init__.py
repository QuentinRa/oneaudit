from oneaudit.api.leaks import LeaksProvider, PasswordHashDataFormat
from name_that_hash import hashes, hash_info


# https://github.com/HashPals/Name-That-Hash
class NameThatHashAPI(LeaksProvider):
    def __init__(self, api_keys):
        super().__init__(
            api_name='nth',
            request_args={},
            api_keys=api_keys,
            show_notice=False
        )
        self.is_endpoint_enabled_for_cracking = self.is_endpoint_enabled
        self.is_endpoint_enabled = False
        self.popular = hash_info.HashInformation().popular
        self.show_notice(self.is_endpoint_enabled_for_cracking)

    def fetch_plaintext_from_hash(self, crackable_hash):
        chash = crackable_hash.strip()

        output = [mode for prototype in hashes.prototypes if prototype.regex.match(chash) for mode in prototype.modes]
        output = [i for i in output if i.name in self.popular] + [i for i in output if i.name not in self.popular]

        return True, PasswordHashDataFormat(
            crackable_hash,
            None,
            output[0].name if len(output) > 0 else None,
            -1 if len(output) == 0 else 40 if output[0].name in self.popular else 20
        )