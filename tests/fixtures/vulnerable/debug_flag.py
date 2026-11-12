"""Vulnerable sample: debug mode left enabled."""

from flask import Flask

app = Flask(__name__)
DEBUG = True


if __name__ == "__main__":
    app.run(debug=True)
