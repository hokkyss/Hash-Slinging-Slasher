# app.py
import os
from typing import Dict

from utils.MainModule import generateKey, proceed
from utils.utils import PrimeGenerator
from flask import Flask, render_template, request, url_for

DEV = os.getenv("FLASK_ENV", "development") == "development"
app = Flask(__name__)

PrimeGenerator.fill()

@app.route("/generation", methods=['POST'])
def generation():
    notification = { "result": "", "public": "", "private": "", "DEV": DEV, "error": "" }
    try:
        [public_key, private_key, filename] = generateKey()

        full_path = "static/" + filename

        f = open(full_path + ".pub", 'w')
        f.write(public_key)
        f.close()

        f = open(full_path + ".pri", 'w')
        f.write(private_key)
        f.close()

        notification["result"] = f"\nKeygen success! Saved as {filename}.pub and {filename}.pri"
        notification["result"] += "\n\nPublic key : " + public_key
        notification["result"] += "\nPrivate key : " + private_key

        if not DEV:
            notification["private"] = url_for('static', filename=f'{filename}.pri')
            notification["public"] = url_for('static', filename=f'{filename}.pub')
        notification["filename"] = filename
    except ValueError as e:
        notification["error"] = str(e)

    return notification

@app.route("/", methods=['GET'])
def home():
    return render_template("home.html")

@app.route("/execute", methods=["POST"])
def execute():
    result: Dict[str, str] = { "result": "", "error": None }
    try:
        public_key = request.json.get("public-key")
        private_key = request.json.get("private-key")
        mode = request.json.get("mode")
        input_box = request.json.get("input-box")
        result_box = proceed(public_key, private_key, mode, input_box)

        if not result_box: result_box = ""
        result["result"] = result_box
    except ValueError as e:
        result["error"] = str(e)

    return result

@app.route("/get-content", methods=["POST"])
def file_content():
    file = request.files.get('file')
    return file.stream.read().decode()

if __name__ == '__main__':
    app.run(debug=DEV)
