import requests
from flask import Flask, request

app = Flask(__name__)

@app.route("/fetch")
def fetch_url():
    # Deliberate SSRF vulnerability to test SentinelReview
    target_url = request.args.get("url")
    response = requests.get(target_url)
    return response.text