"""Safe sample: strong hashing and a random IV per encryption."""

import hashlib
import os


def strong_hash(data):
    digest = hashlib.sha256(data).hexdigest()
    iv = os.urandom(16)
    return digest, iv
