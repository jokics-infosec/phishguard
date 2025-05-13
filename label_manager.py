from googleapiclient.discovery import Resource

PHISHING_LABEL_NAME = "⚠️ PHISHING ALERT"

def get_or_create_label(service: Resource, label_name: str = PHISHING_LABEL_NAME) -> str:
    """
    Checks if a Gmail label exists. Creates it if not.
    
    Returns:
        str: The label ID
    """
    label_id = None
    try:
        response = service.users().labels().list(userId='me').execute()
        labels = response.get('labels', [])
        for label in labels:
            if label['name'].lower() == label_name.lower():
                label_id = label['id']
                break

        if not label_id:
            label_body = {
                'name': label_name,
                'labelListVisibility': 'labelShow',
                'messageListVisibility': 'show'
            }
            created_label = service.users().labels().create(userId='me', body=label_body).execute()
            label_id = created_label['id']

    except Exception as e:
        print(f"[!] Error getting/creating label: {e}")

    return label_id

def apply_label(service: Resource, msg_id: str, label_id: str):
    """
    Applies a Gmail label to a specific email message.
    """
    try:
        service.users().messages().modify(
            userId='me',
            id=msg_id,
            body={'addLabelIds': [label_id]}
        ).execute()
    except Exception as e:
        print(f"[!] Error applying label to message {msg_id}: {e}")
