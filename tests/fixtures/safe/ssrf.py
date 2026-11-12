"""Safe sample: fixed URL plus validated parameters."""

import requests


def fetch_user(user_id):
    return requests.get(
        "https://api.example.com/users", params={"id": user_id}
    )
