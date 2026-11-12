"""Safe sample: secrets come from the environment, never literals."""

import os

api_key = os.environ.get("API_KEY")
password = os.environ["APP_PASSWORD"]
token = os.getenv("AUTH_TOKEN", "")
