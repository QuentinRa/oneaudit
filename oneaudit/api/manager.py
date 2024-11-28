import logging
import time


class DefaultProviderManager:
    def __init__(self, providers):
        self.last_called = {}
        self.providers = providers
        self.logger = logging.getLogger('oneaudit')

    def trigger(self, handler, wait_time):
        now = time.time()
        last_called = self.last_called.get(handler, now)
        time_waited = now - last_called

        self.logger.debug(f"Current time is {now}")
        self.logger.debug(f"Last call to {handler} was at {last_called}: {time_waited}")

        if time_waited < wait_time:
            time_to_wait = wait_time - time_waited
            self.logger.debug(f"We need to wait {time_to_wait}")
            time.sleep(time_to_wait)
        else:
            self.logger.debug(f"We don't need to wait.")

        self.last_called[handler] = time.time()

    def sort_results(self, source, output):
        for k, v in source.items():
            if isinstance(v, list):
                output[k] = sorted([e for e in set(v) if e])
            elif isinstance(v, bool):
                output[k] = v
            else:
                self.logger.error(f"Unexpected type for: k={k} v={v}")
                continue

    def _call_method_on_each_provider(self, result, method_name, *args):
        return self._call_method_on_each_provider_once(result, method_name, False, *args)

    def _call_method_on_each_provider_once(self, result, method_name, stop_when_modified, *args):
        was_modified = False
        for provider in self.providers:
            if not provider.is_endpoint_enabled:
                continue
            provider.logger.info(f"Querying leaks on {provider.api_name} (args={args})")
            for cached, api_result in getattr(provider, method_name, None)(*args):
                if not cached:
                    self.trigger(provider.__class__.__name__, provider.get_rate())
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
            if stop_when_modified and was_modified:
                break

        return was_modified, result