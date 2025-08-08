from flask import Flask, request, jsonify
import os
from dotenv import load_dotenv
import requests
from requests.auth import HTTPBasicAuth
import logging
import boto3
from botocore.exceptions import ClientError
import smtplib
from email.message import EmailMessage

# Load environment variables
load_dotenv()

# Logging setup
logging.basicConfig(
    filename="webhook_test.log",
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)

app = Flask(__name__)

# Environment secrets
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
    logging.info("✅ Webhook received")

    if WEBHOOK_SECRET:
        token = request.headers.get("X-Webhook-Token")
        if token != WEBHOOK_SECRET:
            logging.warning("❌ Invalid webhook token.")
            return jsonify({"error": "Unauthorized"}), 401

    if not request.is_json:
        logging.error("❌ Request is not JSON")
        return jsonify({"error": "Expected application/json"}), 400

    try:
        data = request.get_json()
    except Exception as e:
        logging.error(f"❌ JSON parsing failed: {e}")
        return jsonify({"error": "Malformed JSON"}), 400

    issue = data.get("issue", {})
    issue_key = issue.get("key", "UNKNOWN")
    summary = issue.get("summary", "")
    logging.info(f"Issue: {issue_key}, Summary: {summary}")
    reporter_email = "soumyajyoti.das@sportsbaazi.com"

    aws_msg = create_or_update_aws_user(reporter_email, issue_key)
    add_jira_comment(issue_key, aws_msg)

    # Hardcoded values for Bitbucket
    repo_name = "bb-devops"
    username = "riyasaxena1"
    permission = "read"

    if not username:
        msg = "❌ Username is missing or invalid."
        logging.warning(msg)
        add_jira_comment(issue_key, msg)
        return jsonify({"error": msg}), 400

    if not repo_name:
        msg = "❌ Repository name is missing or invalid."
        logging.warning(msg)
        add_jira_comment(issue_key, msg)
        return jsonify({"error": msg}), 400

    api_url = f"https://api.bitbucket.org/2.0/repositories/{BITBUCKET_WORKSPACE}/{repo_name}/permissions-config/users/{username}"

    try:
        response = requests.put(
            api_url,
            auth=HTTPBasicAuth(BITBUCKET_USERNAME, BITBUCKET_APP_PASSWORD),
            headers={"Content-Type": "application/json"},
            json={"permission": permission}
        )

        logging.info(f"📡 Bitbucket API response: {response.status_code} - {response.text}")

        if response.status_code in [200, 201, 204]:
            msg = f"✅ Granted `{permission}` access to `{username}` on repo `{repo_name}`."
            add_jira_comment(issue_key, msg)
            return jsonify({"message": msg}), 200
        else:
            msg = f"❌ Failed to grant permission: {response.status_code}, {response.text}"
            add_jira_comment(issue_key, msg)
            return jsonify({"error": msg}), 400

    except Exception as e:
        error_msg = f"❌ Exception in Bitbucket call: {e}"
        logging.exception(error_msg)
        add_jira_comment(issue_key, error_msg)
        return jsonify({"error": error_msg}), 500

def add_jira_comment(issue_key, comment):
    if not all([JIRA_BASE_URL, JIRA_AUTH_EMAIL, JIRA_API_TOKEN]):
        logging.warning("⚠️ Jira credentials not set")
        return

    url = f"{JIRA_BASE_URL}/rest/api/3/issue/{issue_key}/comment"
    auth = HTTPBasicAuth(JIRA_AUTH_EMAIL, JIRA_API_TOKEN)
    headers = {"Content-Type": "application/json"}
    payload = {
        "body": {
            "type": "doc",
            "version": 1,
            "content": [
                {
                    "type": "paragraph",
                    "content": [
                        {
                            "type": "text",
                            "text": comment
                        }
                    ]
                }
            ]
        }
    }

    try:
        response = requests.post(url, headers=headers, auth=auth, json=payload)
        logging.info(f"📝 Jira comment status: {response.status_code} - {response.text}")
    except Exception as e:
        logging.exception(f"❌ Jira comment post failed: {e}")

def send_credentials_via_email(to_email, access_key, secret_key):
    msg = EmailMessage()
    msg['Subject'] = 'Your AWS CLI Access Credentials'
    msg['From'] = os.getenv("EMAIL_USERNAME")
    msg['To'] = to_email

    msg.set_content(f"""
Hi,

You've been granted AWS CLI access.

Here are your credentials:

Access Key ID: {access_key}
Secret Access Key: {secret_key}

Please run `aws configure` to set them up. Do not share them with anyone.

Best,
Automation Bot
""")

    try:
        with smtplib.SMTP(os.getenv("EMAIL_HOST"), int(os.getenv("EMAIL_PORT"))) as smtp:
            smtp.starttls()
            smtp.login(os.getenv("EMAIL_USERNAME"), os.getenv("EMAIL_PASSWORD"))
            smtp.send_message(msg)
        logging.info(f"📧 Email sent to {to_email}")
        return True
    except Exception as e:
        logging.exception(f"❌ Failed to send email to {to_email}")
        return False

def create_or_update_aws_user(email, issue_key):
    aws_session = boto3.Session(
        aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
        aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
        region_name=os.getenv("AWS_DEFAULT_REGION")
    )

    iam = aws_session.client("iam")
    user_name = email.split("@")[0].replace(".", "-")

    try:
        iam.get_user(UserName=user_name)
        logging.info(f"👤 IAM user '{user_name}' already exists.")
    except iam.exceptions.NoSuchEntityException:
        try:
            iam.create_user(UserName=user_name)
            logging.info(f"✅ Created user '{user_name}'.")
        except ClientError as e:
            logging.exception("❌ Error creating IAM user")
            return f"❌ Failed to create IAM user: {e}"

    try:
        response = iam.create_access_key(UserName=user_name)
        access_key = response['AccessKey']['AccessKeyId']
        secret_key = response['AccessKey']['SecretAccessKey']

        iam.attach_user_policy(
            UserName=user_name,
            PolicyArn="arn:aws:iam::aws:policy/ReadOnlyAccess"
        )

        success = send_credentials_via_email(email, access_key, secret_key)

        if success:
            return f"✅ AWS CLI access has been emailed to `{email}`."
        else:
            return f"⚠️ User created but failed to email `{email}`. Please check logs."

    except ClientError as e:
        logging.exception("❌ Error generating access key or attaching policy")
        return f"❌ Error during AWS access key generation: {e}"

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    logging.info(f"🚀 Starting server on port {port}")
    app.run(debug=True, host="0.0.0.0", port=port)