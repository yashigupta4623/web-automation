from flask import Flask, request, jsonify
import os
from dotenv import load_dotenv
import json
import requests
from requests.auth import HTTPBasicAuth
import logging
import re

# Load environment variables
load_dotenv()

# Setup logging
logging.basicConfig(
    filename="webhook_test.log",
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)

app = Flask(__name__)

# Secrets
WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET")
BITBUCKET_WORKSPACE = os.getenv("BITBUCKET_WORKSPACE")
BITBUCKET_USERNAME = os.getenv("BITBUCKET_USERNAME")
BITBUCKET_APP_PASSWORD = os.getenv("BITBUCKET_APP_PASSWORD")
JIRA_BASE_URL = os.getenv("JIRA_BASE_URL")
JIRA_AUTH_EMAIL = os.getenv("JIRA_AUTH_EMAIL")
JIRA_API_TOKEN = os.getenv("JIRA_API_TOKEN")


@app.route("/", methods=["GET"])
def health_check():
    return jsonify({"message": "Webhook listener is up"}), 200


@app.route("/", methods=["POST"])
def handle_webhook():
    logging.info("Received webhook call")

    if WEBHOOK_SECRET:
        token = request.headers.get("X-Webhook-Token")
        if token != WEBHOOK_SECRET:
            logging.warning("Invalid webhook token.")
            return jsonify({"error": "Unauthorized"}), 401

    if not request.is_json:
        logging.error("Request is not JSON")
        return jsonify({"error": "Expected application/json"}), 400

    try:
        data = request.get_json()
    except Exception as e:
        logging.error(f"Error parsing JSON: {e}")
        return jsonify({"error": "Malformed JSON"}), 400

    logging.info(f"Raw Body: {request.data.decode('utf-8')}")

    # Parse fields
    issue = data.get("issue", {})
    issue_key = issue.get("key")
    summary = issue.get("summary", "")
    reporter = issue.get("reporter")
    assignee = issue.get("assignee")
    status = data.get("status")

    # Try repo_name from top-level, then labels, then fallback to summary parsing
    repo_name = data.get("repo_name")
    if not repo_name:
        labels = issue.get("labels", [])
        if labels:
            repo_name = labels[0]
        else:
            match = re.search(r"access to ([\w\-]+)", summary)
            if match:
                repo_name = match.group(1)

    username = data.get("username")
    permission = data.get("permission")

    logging.info(f"Issue: {issue_key}, Repo: {repo_name}, User: {username}, Permission: {permission}")

    if not all([repo_name, username, permission]):
        comment = "❌ Missing repo name, permission, or username."
        logging.error(comment)
        add_jira_comment(issue_key, comment)
        return jsonify({"error": "Missing required fields"}), 400

    # Bitbucket API call
    api_url = f"https://api.bitbucket.org/2.0/repositories/{BITBUCKET_WORKSPACE}/{repo_name}/permissions-config/users/{username}"

    try:
        response = requests.put(
            api_url,
            auth=HTTPBasicAuth(BITBUCKET_USERNAME, BITBUCKET_APP_PASSWORD),
            headers={"Content-Type": "application/json"},
            json={"permission": permission}
        )

        if response.status_code in [200, 201, 204]:
            msg = f"✅ Granted `{permission}` access to `{username}` on repo `{repo_name}`."
            logging.info(msg)
            add_jira_comment(issue_key, msg)
        else:
            msg = f"❌ Failed to grant permission: {response.status_code}, {response.text}"
            logging.error(msg)
            add_jira_comment(issue_key, msg)

    except Exception as e:
        error_msg = f"❌ Error during Bitbucket API call: {str(e)}"
        logging.exception(error_msg)
        add_jira_comment(issue_key, error_msg)

    return jsonify({"message": "Webhook processed"}), 200


def add_jira_comment(issue_key, comment):
    if not all([JIRA_BASE_URL, JIRA_AUTH_EMAIL, JIRA_API_TOKEN]):
        logging.warning("Jira credentials not set, skipping comment.")
        return

    url = f"{JIRA_BASE_URL}/rest/api/3/issue/{issue_key}/comment"
    auth = HTTPBasicAuth(JIRA_AUTH_EMAIL, JIRA_API_TOKEN)
    headers = {"Content-Type": "application/json"}
    payload = {"body": comment}

    try:
        response = requests.post(url, headers=headers, auth=auth, json=payload)
        if response.status_code in [200, 201]:
            logging.info(f"📝 Comment added to {issue_key}")
        else:
            logging.error(f"Failed to add comment: {response.status_code}, {response.text}")
    except Exception as e:
        logging.exception(f"Error posting comment to Jira: {e}")


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    logging.info(f"Starting server on port {port}")
    app.run(debug=True, host="0.0.0.0", port=port)