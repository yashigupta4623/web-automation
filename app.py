from flask import Flask, request, jsonify
import os
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET")

@app.route("/", methods=["GET"])
def health_check():
    return jsonify({"message": "Webhook listener is up"}), 200

@app.route("/", methods=["POST"])
def handle_webhook():
    # Debug: Print headers for analysis
    print("Headers Received:")
    for header, value in request.headers.items():
        print(f"{header}: {value}")

    # Check for secret token if configured
    if WEBHOOK_SECRET:
        token = request.headers.get("X-Webhook-Token")  # Change to match Jira header if needed
        if token != WEBHOOK_SECRET:
            print("Invalid webhook token.")
            return jsonify({"error": "Unauthorized"}), 401
    else:
        print("No WEBHOOK_SECRET set in environment. Skipping token check.")

    # Check content type
    if not request.is_json:
        print("Request is not JSON.")
        return jsonify({"error": "Expected application/json"}), 400

    try:
        data = request.get_json()
    except Exception as e:
        print(f"Error parsing JSON: {e}")
        return jsonify({"error": "Malformed JSON"}), 400

    # Print raw body for full inspection (useful for debugging)
    print("\nRaw Body:")
    print(request.data.decode("utf-8"))

    # Parse Jira fields (custom structure)
    issue = data.get("issue", {})
    issue_key = issue.get("key")
    summary = issue.get("summary")
    reporter = issue.get("reporter")
    assignee = issue.get("assignee")
    status = data.get("status")

    print("\nParsed JSON:")
    print(f"Issue Key: {issue_key}")
    print(f"Summary: {summary}")
    print(f"Reporter: {reporter}")
    print(f"Assignee: {assignee}")
    print(f"Status: {status}")

    return jsonify({"message": "Webhook received successfully"}), 200

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"Starting server on port {port}...")
    app.run(debug=True, host="0.0.0.0", port=port)
