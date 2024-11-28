from oneaudit.api.leaks import LeaksAPICapability, PasswordHashDataFormat
from oneaudit.api.leaks.provider import OneAuditLeaksAPIProvider
from name_that_hash import hashes, hash_info


# https://github.com/HashPals/Name-That-Hash
class NameThatHashAPI(OneAuditLeaksAPIProvider):
    def _init_capabilities(self, api_key, api_keys):
        return [LeaksAPICapability.INVESTIGATE_CRACKED_HASHES] if api_key is not None else []

    def __init__(self, api_keys):
        super().__init__(
            api_name='nth',
            request_args={},
            api_keys=api_keys
        )
        self.popular = hash_info.HashInformation().popular

    def lookup_plaintext_from_hash(self, hash_to_crack):
        chash = hash_to_crack.strip()

        output = [mode for prototype in hashes.prototypes if prototype.regex.match(chash) for mode in prototype.modes]
        output = [i for i in output if i.name in self.popular] + [i for i in output if i.name not in self.popular]

        return True, PasswordHashDataFormat(
            value=hash_to_crack,
            plaintext=None,
            format=output[0].name if len(output) > 0 else None,
            format_confidence=-1 if len(output) == 0 else 40 if output[0].name in self.popular else 20
        )