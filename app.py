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
    print("Headers Received:", flush=True)
    for header, value in request.headers.items():
        print(f"{header}: {value}", flush=True)

    # Check for secret token if configured
    if WEBHOOK_SECRET:
        token = request.headers.get("X-Webhook-Token")  # Change to match Jira header if needed
        if token != WEBHOOK_SECRET:
            print("Invalid webhook token.", flush=True)
            return jsonify({"error": "Unauthorized"}), 401
    else:
        print("No WEBHOOK_SECRET set in environment. Skipping token check.", flush=True)

    # Check content type
    if not request.is_json:
        print("Request is not JSON.", flush=True)
        return jsonify({"error": "Expected application/json"}), 400

    try:
        data = request.get_json()
    except Exception as e:
        print(f"Error parsing JSON: {e}", flush=True)
        return jsonify({"error": "Malformed JSON"}), 400

    # Print raw body for full inspection (useful for debugging)
    print("\nRaw Body:", flush=True)
    print(request.data.decode("utf-8"), flush=True)

    # Parse Jira fields (custom structure)
    issue = data.get("issue", {})
    issue_key = issue.get("key")
    summary = issue.get("summary")
    reporter = issue.get("reporter")
    assignee = issue.get("assignee")
    status = data.get("status")

    print("\nParsed JSON:", flush=True)
    print(f"Issue Key: {issue_key}", flush=True)
    print(f"Summary: {summary}", flush=True)
    print(f"Reporter: {reporter}", flush=True)
    print(f"Assignee: {assignee}", flush=True)
    print(f"Status: {status}", flush=True)

    labels = data.get("labels", [])
    repo_name = labels[0] if labels else None
    repo_url = f"https://bitbucket.org/ballebaazi/{repo_name}" if repo_name else "N/A"

    print(f"Repo Name (from label): {repo_name}", flush=True)
    print(f"Repo URL: {repo_url}", flush=True)

    return jsonify({
        "message": "Webhook received successfully",
        "issue_key": issue_key,
        "summary": summary,
        "reporter": reporter,
        "assignee": assignee,
        "status": status,
        "repo_name": repo_name,
        "repo_url": repo_url
    }), 200

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"Starting server on port {port}...", flush=True)
    app.run(debug=True, host="0.0.0.0", port=port)
