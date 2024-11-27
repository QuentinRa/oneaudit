
def args_call_target(objects, args, key, method):
    target = getattr(args, key)
    getattr(objects.get(target, None), method)(args)
