"""Vulnerable sample: weak crypto and hardcoded IV."""

import hashlib

from Crypto.Cipher import DES


def weak_hash(data):
    digest = hashlib.md5(data).hexdigest()
    other = hashlib.sha1(data).hexdigest()
    iv = b"12345678"
    cipher = DES.new(b"8bytekey", DES.MODE_CBC, iv)
    return digest, other, cipher
