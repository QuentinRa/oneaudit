
def args_call_target(objects, args, key, method):
    target = getattr(args, key)
    getattr(objects.get(target, None), method)(args)

def args_add_parsers_to_args(objects, args, key):
    target = getattr(args, key)
    parser = objects.get(target+"_parser", None)
    if parser:
        setattr(args, target+"_parser", parser)
