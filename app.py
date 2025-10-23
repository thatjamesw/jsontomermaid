from flask import Flask, request, make_response
import json
from json_to_mermaid import to_mermaid

# Serve /www both as templates AND as static at the site root
app = Flask(__name__,
            template_folder="www",
            static_folder="www",
            static_url_path="")   # <-- important: static served at "/<file>"

@app.route("/")
def index():
    return open("www/index.html").read()

@app.route("/render", methods=["POST"])
def render_mermaid():
    try:
        text = (request.form.get("jsonText") or "").strip()
        direction = (request.form.get("layout") or "LR").upper()
        if not text and "jsonFile" in request.files and request.files["jsonFile"].filename:
            text = request.files["jsonFile"].read().decode("utf-8")
        if not text:
            return make_response(json.dumps({"ok": False, "error": "No JSON provided"}), 400)

        data = json.loads(text)
        code = to_mermaid(data, direction=direction)

        resp = make_response(json.dumps({"ok": True, "mermaid": code}), 200)
        resp.headers["Content-Type"] = "application/json"
        return resp
    except Exception as e:
        resp = make_response(json.dumps({"ok": False, "error": str(e)}), 400)
        resp.headers["Content-Type"] = "application/json"
        return resp

if __name__ == "__main__":
    app.run(port=5002, debug=True)
