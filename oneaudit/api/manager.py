from oneaudit.utils.logs import get_project_logger
from time import time, sleep


class OneAuditBaseAPIManager:
    """
    A manager is a class that manages multiples APIs (a.k.a. Providers).
    Modules will only interact with the manager and expect to get the results
    regardless of which APIs were used (while they defined which were enabled).

    The manager must ensure that:
    - only enabled providers are invoked
    - rate-limit is respected for each provider
    - results returned to the user are conform to the expected format
    """

    def __init__(self, providers):
        self.last_called = {}
        self.providers = providers
        self.logger = get_project_logger()

    # Result is a dictionary such as { 'toto': [] }
    # And we will append results inside after invoking each provider
    # if 'stop_when_modified', we stop at the first provider that returned a result
    def _call_all_providers(self, result, heading, capability, stop_when_modified, method_name, args):
        was_modified = False
        for provider in self.providers:
            if not provider.is_endpoint_enabled:
                continue

            if capability not in provider.capabilities:
                continue

            provider.logger.info(f"{heading} on {provider.api_name} (args={args})")

            # Call each provider
            for cached, api_result in getattr(provider, method_name, None)(*args):

                # Handle rate-limit
                if not cached:
                    self.handle_rate_limit(provider.__class__.__name__, provider.get_rate())

                # Update result
                for k, v in api_result.items():
                    if not v:
                        continue
                    was_modified = True
                    if isinstance(v, list):
                        result[k].extend(v)
                    elif isinstance(v, bool):
                        result[k] = result[k] or v
                    else:
                        raise Exception(f"Unexpected type for {k}: {type(v)}")

            if stop_when_modified:
                break

        return was_modified, result

    # We apply the rate limit only if the calls to other APIs (e.g., API B, C, etc.) between two calls
    # to the same API (e.g., API A) occur too quickly, not allowing sufficient time to pass.
    def handle_rate_limit(self, handler, wait_time):
        now = time()
        last_called = self.last_called.get(handler, now)
        time_waited = now - last_called

        self.logger.debug(f"Current time is {now}")
        self.logger.debug(f"Last call to {handler} was at {last_called}: {time_waited}")

        if time_waited < wait_time:
            time_to_wait = wait_time - time_waited
            self.logger.debug(f"We need to wait {time_to_wait}")
            sleep(time_to_wait)
        else:
            self.logger.debug(f"We don't need to wait.")

        self.last_called[handler] = time()