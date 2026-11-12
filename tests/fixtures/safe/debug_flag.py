"""Safe sample: debug mode off."""

import os

from flask import Flask

app = Flask(__name__)
DEBUG = False


if __name__ == "__main__":
    app.run(debug=os.getenv("DEBUG") == "1")
