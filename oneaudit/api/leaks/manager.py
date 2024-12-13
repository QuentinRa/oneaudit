from oneaudit.api.manager import OneAuditBaseAPIManager
from oneaudit.api.leaks import LeaksAPICapability, PasswordHashDataFormat, LeakTarget
from oneaudit.api.leaks import aura, hashmob, hudsonrocks, leakcheck
from oneaudit.api.leaks import nth, proxynova, snusbase, spycloud
from oneaudit.api.leaks import whiteintel, enzoic
from oneaudit.utils.io import serialize_api_object
from collections import Counter
from dataclasses import asdict
from hashlib import sha1, md5
from bcrypt import hashpw
from re import compile


def _email_cleaner(email):
    """
    We sometimes see "JOHN.DOE@EXAMPLE.COM"
    or " john.doe@example.com" due to some providers/databases returning them like that.
    We do miss some leaks by casting all of them to lowercase, but this makes the managment easier.
    """
    return email.strip().lower()


class OneAuditLeaksAPIManager(OneAuditBaseAPIManager):
    """
    APIs related to leaks
    """
    def __init__(self, api_keys, can_use_cache_even_if_disabled):
        super().__init__([
            # FREE
            aura.AuraAPI(api_keys),
            nth.NameThatHashAPI(api_keys),
            proxynova.ProxyNovaAPI(api_keys),
            leakcheck.LeakCheckFreeAPI(api_keys),
            # FREEMIUM
            enzoic.EnzoicAPI(api_keys),
            hudsonrocks.HudsonRocksAPI(api_keys),
            hashmob.HashMobAPI(api_keys),
            spycloud.SpyCloudAPI(api_keys),
            whiteintel.WhiteIntelAPI(api_keys),
            # PAID
            leakcheck.LeakCheckPaidAPI(api_keys),
            snusbase.SnusbaseAPI(api_keys),
        ])
        self.can_use_cache_even_if_disabled = can_use_cache_even_if_disabled

    def investigate_leaks(self, credentials, candidates):
        results = {}
        bcrypt_hash_regex = compile(r'(^\$2[aby]\$[0-9]{2}\$[A-Za-z0-9./]{22})')

        try:
            # noinspection PyTypeChecker
            domain_candidates = [asdict(LeakTarget(email, True, False, [email], {})) for email in candidates]
            all_emails = [_email_cleaner(email) for credential in credentials + domain_candidates for email in credential['emails']]
            list(self._call_all_providers(
                heading="Processing bulk queries",
                capability=LeaksAPICapability.INVESTIGATE_BULK,
                method_name='investigate_bulk',
                args=(all_emails,)
            ))

            for credential in credentials + domain_candidates:
                key = _email_cleaner(credential['login'])
                if key in results:
                    continue

                results[key] = {
                    'logins': [],
                    'passwords': [],
                    'censored_logins': [],
                    'censored_passwords': [],
                    'raw_hashes': [],
                    'info_stealers': [],
                    'breaches': [],
                    'verified': False,
                    'employed': credential['employed'],
                }

                # Clean every email in "emails"
                credential['emails'] = [_email_cleaner(email) for email in credential['emails']]

                # Get the leaks per email, and save them in the record associated with the login
                for email in credential['emails']:
                    was_modified, results[key] = self._call_all_providers_dict(
                        heading="Investigate leaks",
                        capability=LeaksAPICapability.INVESTIGATE_LEAKS_BY_EMAIL,
                        stop_when_modified=False,
                        method_name='investigate_leaks_by_email',
                        result=results[key],
                        args=(email,)
                    )
                    if was_modified and email == key:
                        credential['verified'] = True
                        self.logger.debug(f"Email {email} was verified due to leaks associated to it.")

                # Handle new logins
                for login in results[key]["logins"]:
                    login = _email_cleaner(login)
                    if "@" not in login or ':' in login or login in credential['emails']:
                        continue
                    raise Exception(f"Found new email that was not handled: {login}")
                results[key]['logins'].extend(credential['emails'])

                # Use the value in credential that may have been updated
                results[key]['verified'] = credential['verified']

                # Attempt to crack hashes
                uncracked_hashes = []
                if results[key]['raw_hashes']:
                    # We need to remove any hash for which we already have the passwords
                    # We need to handle cases where the hash is just of checksum of the login
                    # (as it happened multiple times for such hashes to be found, such as with gravatar leak, etc.)
                    known_hashes = []
                    candidates = [key] + results[key]['passwords'] + results[key]['logins']
                    for password in candidates:
                        known_hashes.append(md5(password.encode()).hexdigest())
                        known_hashes.append(sha1(password.encode()).hexdigest())

                    for hash_to_crack in results[key]['raw_hashes']:
                        hash_to_crack = hash_to_crack.strip()

                        # No need to crack these
                        if not hash_to_crack or hash_to_crack in known_hashes:
                            continue

                        # We need to crack it, or at least, investigate it
                        hash_data = self._find_plaintext_from_hash(hash_to_crack)

                        # If uncracked, add the hash to the list, otherwise
                        # Add the password to the list
                        if hash_data.plaintext is None:
                            # At the very list, try to check if we don't already have the password
                            match = bcrypt_hash_regex.match(hash_to_crack)
                            if match:
                                salt = match.group(1)
                                for password in results[key]['passwords']:
                                    try:
                                        known_hashes.append(hashpw(password.encode(), salt.encode()))
                                    except ValueError:
                                        pass
                                if hash_to_crack in known_hashes:
                                    continue

                            uncracked_hashes.append(hash_data)
                        else:
                            known_hashes.append(md5(hash_data.plaintext.encode()).hexdigest())
                            known_hashes.append(sha1(hash_data.plaintext.encode()).hexdigest())
                            results[key]['passwords'].append(hash_data.plaintext)

                results[key]['hashes'] = uncracked_hashes
                del results[key]['raw_hashes']

                # Sort every value and remove duplicates
                results[key] = self.sort_dict(results[key])
        except KeyboardInterrupt:
            pass

        return [{"login": key, **value} for key, value in results.items()]

    def investigate_domain(self, domain):
        results = {
            'leaked_urls': [],
            'censored_creds': [],
            'censored_stealers': [],
            'emails': [],
        }
        if not domain:
            return results
        _, results = self._call_all_providers_dict(
            heading="Investigate domain",
            capability=LeaksAPICapability.INVESTIGATE_LEAKS_BY_DOMAIN,
            stop_when_modified=False,
            method_name='investigate_leaks_by_domain',
            result=results,
            args=(domain,)
        )
        return self.sort_dict(results)

    def compute_stats(self, credentials):
        stats = {
            'passwords': {},
            'censored_passwords': {},
            'hashes': {},
            'info_stealers': {},
            'breaches': {},
        }
        breach_per_provider = {}
        password_length_per_provider = {}
        for credential in credentials:
            # We need to inspect the results for EACH login
            # If a user has two emails, we want to know the cumulated stats
            # (e.g. one password 'abc' for a@b.c and one password 'abc' for a@d.e as counted as two
            #   passwords as the login is different even if the user that own the two emails is the same)
            found_passwords = []
            for login in credential['logins']:
                login = _email_cleaner(login)

                # While not necessary, it will reduce the number of queries
                # to the cache, as we won't look for logins that are not emails
                if "@" not in login or " " in login or ":" in login:
                    continue

                for api_provider, api_result in self._call_all_providers(
                        heading="Investigate leaks",
                        capability=LeaksAPICapability.INVESTIGATE_LEAKS_BY_EMAIL,
                        method_name='investigate_leaks_by_email',
                        args=(login, True)):
                    for key, entries in api_result.items():
                        if key == 'raw_hashes':
                            entries = [self._find_plaintext_from_hash(entry) for entry in entries]
                            key = 'hashes'
                        if key in ['breaches', 'hashes', 'info_stealers']:
                            entries = [serialize_api_object(entry) for entry in entries]
                        if key not in stats:
                            continue

                        for entry in entries:
                            local_key = key
                            if entry not in credential[local_key]:
                                if local_key == 'hashes' and entry['plaintext']:
                                    local_key = 'passwords'
                                    entry = entry['plaintext']
                                else:
                                    continue
                            entry_key = f"{login}.{entry}"
                            if entry_key not in stats[local_key]:
                                stats[local_key][entry_key] = []
                            stats[local_key][entry_key].append(api_provider.api_name)

                            if local_key == 'passwords':
                                found_passwords.append(entry)

                                # Compute password size stats
                                if api_provider.api_name not in password_length_per_provider:
                                    password_length_per_provider[api_provider.api_name] = []
                                password_length_per_provider[api_provider.api_name].append(len(entry))

                            if local_key == 'breaches':
                                if api_provider.api_name not in breach_per_provider:
                                    breach_per_provider[api_provider.api_name] = []
                                breach_per_provider[api_provider.api_name].append(entry['source'])

            # We kept track of the password we found as some may have been generated/added externally/not in the cache
            login = _email_cleaner(credential['login'])
            for password in credential['passwords']:
                if password in found_passwords:
                    continue
                stats['passwords'][f"{login}.{password}"] = ['unknown']
                if 'unknown' not in password_length_per_provider:
                    password_length_per_provider['unknown'] = []
                password_length_per_provider['unknown'].append(len(password))

        # Only keep the top 10 sources
        for provider, breaches in breach_per_provider.items():
            source_counts = Counter(breaches)
            top_sources = source_counts.most_common(10)
            breach_per_provider[provider] = top_sources

        # Only keep the top 5 password lengths
        for provider, lengths in password_length_per_provider.items():
            length_counts = Counter(lengths)
            top_lengths = length_counts.most_common(5)
            password_length_per_provider[provider] = top_lengths

        final_stats = {}
        for attribute_name, entries in stats.items():
            stats_per_provider = {provider.api_name:{'all': 0, 'exclusive': 0} for provider in self.providers}
            stats_per_provider['unknown'] = {'all': 0, 'exclusive': 0}

            # Compute the exclusive/all values for each provider for this specific attribute
            for identifier, values in entries.items():
                values = list(set(values))
                if len(values) == 1:
                    stats_per_provider[values[0]]['exclusive'] += 1
                    stats_per_provider[values[0]]['all'] += 1
                else:
                    for value in values:
                        stats_per_provider[value]['all'] += 1

            final_stats[attribute_name] = (stats_per_provider, len(entries))

        return final_stats, breach_per_provider, password_length_per_provider

    def sort_dict(self, results):
        # Sort every value and remove duplicates
        for k, v in results.items():
            if isinstance(v, list):
                results[k] = sorted([e for e in set(v) if e])
            elif isinstance(v, bool):
                results[k] = v
            else:
                self.logger.error(f"Unexpected type for: k={k} v={v}")
                continue
        return results

    def _find_plaintext_from_hash(self, hash_to_crack):
        hash_data = PasswordHashDataFormat(hash_to_crack, None, None, -1)
        for _, api_result in self._call_all_providers(
                heading="Attempt to find plaintext from hash",
                capability=LeaksAPICapability.INVESTIGATE_CRACKED_HASHES,
                method_name='lookup_plaintext_from_hash',
                args=(hash_to_crack,)):
            hash_data = PasswordHashDataFormat(
                hash_to_crack,
                api_result.plaintext if api_result.plaintext else hash_data.plaintext,
                api_result.format if hash_data.format_confidence < api_result.format_confidence else hash_data.format,
                api_result.format_confidence if hash_data.format_confidence < api_result.format_confidence else hash_data.format_confidence,
            )
            if hash_data.plaintext:
                break
        return hash_data