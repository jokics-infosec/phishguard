from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import InstalledAppFlow
import base64
from email import message_from_bytes

# Allow read + label access
SCOPES = ['https://www.googleapis.com/auth/gmail.modify']

def get_gmail_service():
    """
    Authenticates and returns a Gmail API service object.
    """
    creds = None
    try:
        creds = Credentials.from_authorized_user_file('token.json', SCOPES)
    except:
        flow = InstalledAppFlow.from_client_secrets_file(
            'credentials-gmail.json', SCOPES)
        creds = flow.run_local_server(port=0)
        with open('token.json', 'w') as token:
            token.write(creds.to_json())

    return build('gmail', 'v1', credentials=creds)

def fetch_unread_emails(service, max_results=5):
    """
    Fetches a list of unread emails and returns basic metadata + MIME object.

    Returns:
        list of dicts: [{from, subject, body (MIME msg), id}]
    """
    messages = []
    try:
        results = service.users().messages().list(
            userId='me', labelIds=['INBOX'], q='is:unread', maxResults=max_results
        ).execute()
        msg_ids = results.get('messages', [])

        for msg in msg_ids:
            msg_data = service.users().messages().get(
                userId='me', id=msg['id'], format='raw').execute()

            raw_msg = base64.urlsafe_b64decode(msg_data['raw'].encode('ASCII'))
            mime_msg = message_from_bytes(raw_msg)

            messages.append({
                "id": msg['id'],
                "from": mime_msg.get('From'),
                "subject": mime_msg.get('Subject'),
                "body": mime_msg
            })

    except Exception as e:
        print(f"[!] Error fetching emails: {e}")

    return messages
