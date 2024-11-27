from dataclasses import asdict, is_dataclass
import json

class GenericObjectEncoder(json.JSONEncoder):
    def default(self, obj):
        if hasattr(obj, 'to_dict'):
            return obj.to_dict()
        if is_dataclass(obj):
            return asdict(obj)
        return super().default(obj)


def save_to_json(output_file, obj):
    with open(output_file, 'w', encoding='utf-8') as output_file:
        json.dump(obj, output_file, indent=4)