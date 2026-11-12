"""Vulnerable sample: path traversal via constructed paths."""


def read_user_file(filename):
    with open(f"/data/{filename}") as handle:
        return handle.read()


def read_other_file(filename):
    with open("/data/" + filename) as handle:
        return handle.read()
