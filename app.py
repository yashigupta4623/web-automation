from flask import Flask, request, jsonify
import os
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET")

@app.route("/", methods=["POST"])
def handle_webhook():
    # Get and verify the X-Webhook-Token header
    token = request.headers.get("X-Webhook-Token")
    if token != WEBHOOK_SECRET:
        return jsonify({"error": "Unauthorized"}), 401

    # Parse the incoming JSON payload
    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid or missing JSON"}), 400

    # Log or process issue data
    issue_key = data.get("key")
    summary = data.get("summary")
    status = data.get("status")

    print(f"Issue Key: {issue_key}")
    print(f"Summary: {summary}")
    print(f"Status: {status}")

    # Here you can add your Bitbucket repo access logic or anything else
    # Example: trigger a shell script, call an API, etc.

    return jsonify({"message": "Webhook received successfully"}), 200

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))