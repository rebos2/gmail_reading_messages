import os.path
import json
import base64
import re

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from bs4 import BeautifulSoup

# If modifying these scopes, delete the file token_email.json.
SCOPES = ["https://mail.google.com/"]


def auth(email):
    creds = None
    if os.path.exists(f"token_{email}.json"):
        creds = Credentials.from_authorized_user_file(f"token_{email}.json", SCOPES)
    # If there are no (valid) credentials available, let the user log in.
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                "credentials.json", SCOPES
            )
            creds = flow.run_local_server(port=0)
        # Save the credentials for the next run
        with open(f"token_{email}.json", "w") as token:
            token.write(creds.to_json())
    return creds


def branch_mimeType(branch):
    if branch["mimeType"] == "text/html":
        data = branch["body"]["data"]
        data = base64.urlsafe_b64decode(data)
        data = BeautifulSoup(data, "lxml", from_encoding="utf-8").text
        data = re.sub("\s+", " ", data)
        return [{"part_type": "html", "data": data}]
    elif branch["mimeType"] == "text/plain":
        data = branch["body"]["data"]
        data = base64.urlsafe_b64decode(data)
        data = data.decode("UTF-8")
        data = re.sub("\s+", " ", data)
        return [{"part_type": "plain", "data": data}]
    elif branch["mimeType"].startswith("image"):
        return [{"part_type": "image", "data": []}]
    elif branch["mimeType"].startswith("audio"):
        return [{"part_type": "audio", "data": []}]
    elif branch["mimeType"].startswith("application"):
        return [{"part_type": "application", "data": []}]
    elif branch["mimeType"] == "text/calendar":
        return [{"part_type": "calendar", "data": []}]
    elif branch["mimeType"].startswith("multipart"):
        if "data" in branch["body"]:
            print(branch)
        ret = []
        if "parts" in branch:
            for part in branch["parts"]:
                ret.extend(branch_mimeType(part))
        return [{"part_type": "multipart", "data": ret}]
    else:
        return [{"part_type": f"unknown: {branch['mimeType']}", "data": []}]


def check_data(message_id, data, messages_for_check):
    compact_data = []
    for dt in data:
        if dt["part_type"].startswith("unknown"):
            if message_id not in messages_for_check:
                messages_for_check.append(message_id)
        elif dt["part_type"] != "multipart":
            if dt["data"]:
                compact_data.append(dt["data"])
        else:  # "part_type" = multipart
            multipart_data, messages_for_check = check_data(message_id, dt["data"], messages_for_check)
            compact_data.extend(multipart_data)
    return compact_data, messages_for_check


def main(max_mails, email):
    # Select the required email
    creds = auth(email)
    try:
        # Call the Gmail API
        service = build("gmail", "v1", credentials=creds)
        # Searching for inbox messages
        inbox_messages = service.users().messages().list(userId="me", labelIds="INBOX", maxResults=max_mails).execute()
        messages = inbox_messages.get("messages", [])
        if not messages:
            print("No messages found")
        else:
            print(f"Messages found: {len(messages)}\nMessage processing:")
            total_messages = []
            messages_for_check = []
            for message in messages:
                print(f"{messages.index(message) + 1}/{len(messages)}")
                msg = service.users().messages().get(userId="me", id=message["id"], format="full").execute()

                # Getting the sender of the message and the subject of the message
                email_from = ""
                subject = ""
                for hdr in msg["payload"]["headers"]:
                    if hdr["name"].lower() == "from":
                        email_from = hdr["value"]
                    elif hdr["name"].lower() == "subject":
                        subject = hdr["value"]
                # Getting message data
                data = branch_mimeType(msg["payload"])
                compact_data, messages_for_check = check_data(msg["id"], data, messages_for_check)

                total_messages.append({
                    "id": msg["id"],
                    "from": email_from,
                    "subject": subject,
                    "data": compact_data
                })

            print(f"\nReady messages: {len(total_messages)}\nMessages for check: {len(messages_for_check)}")
            # Creating a result dictionary. "check" contains the messages id that need to be checked
            result = {
                "messages": total_messages,
                "check": messages_for_check
            }
            with open("result.json", "w", encoding="utf-8") as file:
                json.dump(result, file, indent=4, ensure_ascii=False)
    except Exception as error:
        print(f"Error: {error}")


def change_labels(email):
    # Select the required email
    creds = auth(email)
    try:
        # Call the Gmail API
        service = build("gmail", "v1", credentials=creds)

        # TODO Select message id
        message_id = "18bc90e69270b304"

        labels = service.users().labels().list(userId="me").execute()
        labels = labels.get("labels", [])
        print("Labels:")
        for label in labels:
            print(f"Name: {label['name']}\t---->\tid: {label['id']}")

        # TODO Select label id to add or remove
        label_dict = {
            "addLabelIds": [],
            "removeLabelIds": ["STARRED"]
        }

        msg = service.users().messages().get(userId="me", id=message_id, format="full").execute()
        print(f"\nBefore:\n{msg['labelIds']}")
        service.users().messages().modify(userId="me", id=message_id, body=label_dict).execute()
        msg = service.users().messages().get(userId="me", id=message_id, format="full").execute()
        print(f"After:\n{msg['labelIds']}")
    except Exception as error:
        print(f"Error: {error}")


if __name__ == "__main__":
    # Number of messages viewed (maximum 500). The name of the token's json file for authorization
    # main(max_mails="50", email="onedleaf")

    # Example of working with labels
    change_labels(email="onedleaf")
