"""Vulnerable sample: SSRF-prone URL construction."""

import requests

BASE_URL = "https://internal.example.com"


def fetch_user_url(user_url):
    return requests.get(f"https://example.com/{user_url}")


def fetch_path(path):
    return requests.get(BASE_URL + path)
