
import json
import imaplib
import email

class GmailConnector:
    def __init__(self, credentials_path="credentials.json"):
        self.imap = None
        self.email = None
        self.password = None
        self.credentials_path = credentials_path

    def load_credentials(self):
        with open(self.credentials_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        self.email = data.get("email")
        self.password = data.get("app_password")

    def connect_imap(self):
        if not self.email or not self.password:
            raise ValueError("Credentials not loaded. Call load_credentials first.")
        self.imap = imaplib.IMAP4_SSL("imap.gmail.com")
        self.imap.login(self.email, self.password)

    def logout(self):
        if self.imap:
            try:
                self.imap.logout()
            finally:
                self.imap = None

    def list_emails(self, mailbox="INBOX", limit=None):
        """List emails from the mailbox. Returns a list of dicts with 'from', 'date', 'subject', 'uid'. Only fetches headers for speed."""
        if not self.imap:
            raise RuntimeError("IMAP connection not established.")
        self.imap.select(mailbox)
        typ, data = self.imap.search(None, "ALL")
        if typ != "OK":
            return []
        uids = data[0].split()
        if limit is not None:
            uids = uids[-limit:]
        emails = []
        for uid in reversed(uids):
            typ, msg_data = self.imap.fetch(uid, '(BODY.PEEK[HEADER.FIELDS (FROM SUBJECT DATE)])')
            if typ != "OK":
                continue
            # msg_data[0][1] is the raw header bytes
            headers = email.message_from_bytes(msg_data[0][1])
            emails.append({
                "from": headers.get("From", ""),
                "date": headers.get("Date", ""),
                "subject": headers.get("Subject", ""),
                "uid": uid.decode() if isinstance(uid, bytes) else str(uid)
            })
        return emails

    def _fetch_email(self, uid):
        typ, msg_data = self.imap.fetch(uid, "(RFC822)")
        if typ != "OK":
            return None
        return email.message_from_bytes(msg_data[0][1])