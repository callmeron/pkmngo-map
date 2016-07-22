#!/usr/bin/python
import os
import pkmn_api
from flask import Flask, request, send_from_directory
app = Flask(__name__)

@app.route("/")
def root():
    return send_from_directory('web', 'index.html')

@app.route('/<path:path>')
def serve(path):
    return send_from_directory('web', path)

if __name__ == "__main__":

    config = {
        "USERNAME":os.environ.get('PGO_PASSWORD', "Invalid"),
        "PASSWORD":os.environ.get('PGO_PASSWORD', "Invalid"),
        "LOCATION":os.environ.get('PGO_LOCATION', "Invalid"),
        "DEBUG":False
    }

    pkmn_api.init(config,stay=True)
    app.run(host='0.0.0.0', port=8000)
