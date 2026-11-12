"""Safe sample: safe parsing only."""

import ast
import json

import yaml


def load_data(data, text, literal):
    obj = json.loads(data)
    config = yaml.safe_load(text)
    value = ast.literal_eval(literal)
    return obj, config, value
