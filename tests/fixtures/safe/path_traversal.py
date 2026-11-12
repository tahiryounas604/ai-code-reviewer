"""Safe sample: fixed paths only, no user-built paths."""

import os

BASE_DIR = "/data"


def read_config():
    with open("config.json") as handle:
        return handle.read()


def read_data_file():
    with open(os.path.join(BASE_DIR, "data.txt")) as handle:
        return handle.read()
