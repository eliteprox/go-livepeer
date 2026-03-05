"""Simple BYOC worker: reverses text. See doc/byoc.md for usage."""
from flask import Flask, request, Response
import json

app = Flask(__name__)


@app.route("/reverse-text", methods=["POST"])
def reverse_text():
    content = request.get_json(silent=True) or {}
    text = content.get("text", "")
    reversed_text = text[::-1]
    return Response(
        json.dumps({"original": text, "reversed": reversed_text}),
        mimetype="application/json",
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
