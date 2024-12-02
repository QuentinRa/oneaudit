from dataclasses import asdict, is_dataclass
from json import JSONEncoder, dump
from os.path import isabs, join, abspath
from os import getcwd


def serialize_api_object(obj):
    if hasattr(obj, 'to_dict'):
        return obj.to_dict()
    if is_dataclass(obj):
        return asdict(obj)
    return None


class GenericObjectEncoder(JSONEncoder):
    def default(self, obj):
        res = serialize_api_object(obj)
        return super().default(obj) if not res else obj


def save_to_json(output_file, obj):
    with open(output_file, 'w', encoding='utf-8') as output_file:
        dump(obj, output_file, cls=GenericObjectEncoder, indent=4)


def to_absolute_path(filepath):
    if not isabs(filepath):
        filepath = join(getcwd(), filepath)
    return abspath(filepath)
