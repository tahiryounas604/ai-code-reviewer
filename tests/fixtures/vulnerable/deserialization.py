"""Vulnerable sample: unsafe deserialization and dynamic code execution."""

import pickle

import yaml


def load_data(data, text, user_input, code):
    obj = pickle.loads(data)
    config = yaml.load(text)
    result = eval(user_input)
    exec(code)
    return obj, config, result
