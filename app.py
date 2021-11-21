# app.py
import os
from typing import Dict

from utils.MainModule import generateKey, proceed
from utils.utils import PrimeGenerator
from flask import Flask, render_template, request, url_for

DEV = os.getenv("FLASK_ENV", "development") == "development"
app = Flask(__name__)
app.config['SECRET_KEY'] = 'UNTUK_SESSION'

PrimeGenerator.fill()

@app.route("/generation", methods=['POST'])
def generation():
    notification = { "result": "", "public": "", "private": "", "error": "" }
    try:
        [public_key, private_key, filename] = generateKey()

        f = open(os.path.join(app.static_folder, f'{filename}.pub'), 'w')
        f.write(public_key)
        f.close()

        f = open(os.path.join(app.static_folder, f'{filename}.pri'), 'w')
        f.write(private_key)
        f.close()

        notification["result"] = f"\nKeygen success! Saved as {filename}.pub and {filename}.pri"
        notification["result"] += "\n\nPublic key : " + public_key
        notification["result"] += "\nPrivate key : " + private_key

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
    result: Dict[str, str] = {
        "result": "",
        "error": None,
        "full": None,
        "sign": None,
        "content": None,
        "notification": ""
    }

    try:
        public_key = request.json.get("public-key")
        private_key = request.json.get("private-key")
        mode = request.json.get("mode")
        input_box = request.json.get("input-box") + "\n"
        result_box = proceed(public_key, private_key, mode, input_box)

        if not result_box: result_box = ""
        result["result"] = result_box

        if mode == 'Sign':
            f = open(os.path.join(app.static_folder, 'content.txt'), 'w')
            f.write(input_box)
            f.close()

            f = open(os.path.join(app.static_folder, f'sign.txt'), 'w')
            f.write(result_box)
            f.close()

            f = open(os.path.join(app.static_folder, f'signed.txt'), 'w')
            f.write(input_box + result_box)
            f.close()

            result["full"] = url_for('static', filename='signed.txt')
            result["sign"] = url_for('static', filename='sign.txt')
            result["content"] = url_for('static', filename='content.txt')
            result["notification"] = 'You successfully signed the document. You can download both sign and the content separately.'
        elif mode == 'Verify':
            f = open(os.path.join(app.static_folder, 'content.txt'), 'w')
            f.write(input_box)
            f.close()
            result["full"] = url_for('static', filename='content.txt')
            result["notification"] = 'You can view the content!'

    except ValueError as e:
        result["error"] = str(e)

    return result

@app.route("/get-content", methods=["POST"])
def file_content():
    file = request.files.get('file')
    return file.stream.read().decode()

if __name__ == '__main__':
    app.run(debug=DEV)
