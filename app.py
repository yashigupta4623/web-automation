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
import threading
import json

import time

# Temporary AWS credentials lifetime (in seconds)
TEMP_USER_LIFETIME_SECONDS = 7200  # 2 hours

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
    reporter_email = "riya.saxena@sportsbaazi.com"
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

def send_credentials_via_email(to_email, access_key, secret_key, session_token=None, expiration=None):
    import smtplib
    from email.message import EmailMessage
    import logging
    import os

    msg = EmailMessage()
    msg['Subject'] = 'Your AWS CLI Access Credentials'
    msg['From'] = os.getenv("EMAIL_FROM")
    msg['To'] = to_email

    content = f"""
Hi {to_email},

You've been granted AWS CLI access.

🔐 Access Key ID: {access_key}
🔐 Secret Access Key: {secret_key}
"""

    if session_token:
        content += f"🔐 Session Token: {session_token}\n"

    if expiration:
        content += f"⏰ Credentials expire at: {expiration}\n"

    content += """
Please run `aws configure` in your terminal and paste these keys when asked.
Do not share these credentials with anyone.

Best,
Automation Bot
"""

    msg.set_content(content)

    try:
        logging.info(f"📧 Connecting to SMTP: {os.getenv('SMTP_HOST')}:{os.getenv('SMTP_PORT')}")
        with smtplib.SMTP(os.getenv("SMTP_HOST"), int(os.getenv("SMTP_PORT"))) as smtp:
            smtp.set_debuglevel(1)  # Print raw SMTP communication to logs
            if os.getenv("SMTP_SECURITY", "").upper() == "STARTTLS":
                smtp.starttls()
            smtp.login(os.getenv("SMTP_USERNAME"), os.getenv("SMTP_PASSWORD"))
            smtp.send_message(msg)
        logging.info(f"✅ Email sent to {to_email}")
        return True
    except Exception as e:
        logging.exception(f"❌ Failed to send email to {to_email}")
        return False

def delete_role_after_delay(role_name, delay_seconds):
    def delete_role():
        time.sleep(delay_seconds)
        aws_session = boto3.Session(
            aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
            aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
            region_name=os.getenv("AWS_DEFAULT_REGION")
        )
        iam = aws_session.client("iam")
        try:
            # List attached policies
            attached_policies = iam.list_attached_role_policies(RoleName=role_name)
            for policy in attached_policies.get('AttachedPolicies', []):
                policy_arn = policy['PolicyArn']
                logging.info(f"Detaching policy {policy_arn} from role {role_name}")
                iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
            # Delete the role
            logging.info(f"Deleting IAM role {role_name}")
            iam.delete_role(RoleName=role_name)
            logging.info(f"IAM role {role_name} deleted successfully")
        except Exception as e:
            logging.exception(f"Failed to delete IAM role {role_name}: {e}")

    thread = threading.Thread(target=delete_role)
    thread.daemon = True
    thread.start()

def create_or_update_aws_user(email, issue_key):
    aws_session = boto3.Session(
        aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
        aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
        region_name=os.getenv("AWS_DEFAULT_REGION")
    )
    iam = aws_session.client("iam")
    sts = aws_session.client("sts")

    # Generate unique names
    safe_email = email.replace('@', '_').replace('.', '_')
    role_name = f"{safe_email}_temp_role"
    user_name = email.replace('@', '_').replace('.', '_')

    try:
        # 1. Check if IAM user exists, else create it
        user_exists = False
        try:
            iam.get_user(UserName=user_name)
            user_exists = True
        except iam.exceptions.NoSuchEntityException:
            # Create the user
            iam.create_user(UserName=user_name)
            user_exists = True
        except Exception as e:
            logging.exception(f"Failed to get or create IAM user {user_name}")
            return f"❌ Error getting or creating IAM user: {e}"

        # 2. Delete any existing IAM role for the email before creating a new one
        try:
            iam.get_role(RoleName=role_name)
            attached_policies = iam.list_attached_role_policies(RoleName=role_name)
            for policy in attached_policies.get('AttachedPolicies', []):
                iam.detach_role_policy(RoleName=role_name, PolicyArn=policy['PolicyArn'])
            iam.delete_role(RoleName=role_name)
            time.sleep(5)
        except iam.exceptions.NoSuchEntityException:
            pass

        # 3. Create trust policy with the user's ARN (dynamically get account id)
        iam_user_arn = f"arn:aws:iam::{sts.get_caller_identity()['Account']}:user/{user_name}"
        trust_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": iam_user_arn},
                    "Action": "sts:AssumeRole"
                }
            ]
        }

        # 4. Create the new IAM role
        iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(trust_policy),
            Description="Temporary role for AWS CLI access via webhook automation",
            MaxSessionDuration=TEMP_USER_LIFETIME_SECONDS
        )
        time.sleep(5)

        # 5. Attach ReadOnlyAccess policy to the role
        iam.attach_role_policy(
            RoleName=role_name,
            PolicyArn="arn:aws:iam::aws:policy/ReadOnlyAccess"
        )

        # 6. Create access keys for the IAM user (always create, not reuse)
        try:
            access_key_resp = iam.create_access_key(UserName=user_name)
            user_access_key = access_key_resp['AccessKeyId']
            user_secret_key = access_key_resp['SecretAccessKey']
        except ClientError as e:
            logging.exception(f"Failed to create access key for user {user_name}")
            return f"❌ Error creating access key for user: {e}"

        # Send the user's credentials (not role credentials) via email
        email_success = send_credentials_via_email(email, user_access_key, user_secret_key)

        # Now, continue with the rest of the flow: assume role, email credentials, schedule deletion
        account_id = sts.get_caller_identity()["Account"]
        role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
        role_details = iam.get_role(RoleName=role_name)
        max_session_duration = role_details['Role']['MaxSessionDuration']
        response = sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName=f"{safe_email}_session",
            DurationSeconds=min(TEMP_USER_LIFETIME_SECONDS, max_session_duration)
        )
        credentials = response['Credentials']
        access_key = credentials['AccessKeyId']
        secret_key = credentials['SecretAccessKey']
        session_token = credentials['SessionToken']
        expiration = credentials['Expiration'].strftime("%Y-%m-%d %H:%M:%S UTC")

        # Email the temporary credentials as well (optional, or you may combine messaging)
        send_credentials_via_email(email, access_key, secret_key, session_token, expiration)

        # Schedule role deletion
        delete_role_after_delay(role_name, TEMP_USER_LIFETIME_SECONDS)

        if email_success:
            return (f"✅ AWS CLI user credentials and temporary role credentials have been emailed to `{email}`. "
                    f"The temporary IAM role `{role_name}` will be deleted after expiration at {expiration}.")
        else:
            return f"⚠️ Temporary credentials generated but failed to email `{email}`. Please check logs."

    except ClientError as e:
        logging.exception("❌ Error generating temporary AWS credentials")
        return f"❌ Error during AWS temporary credentials generation: {e}"

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    logging.info(f"🚀 Starting server on port {port}")
    app.run(debug=True, host="0.0.0.0", port=port)