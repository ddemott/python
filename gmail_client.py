

import json
import os
import imaplib
import email

class GmailConnector:
    EMAIL_CACHE_FILE = "email_headers_cache.json"

    def load_email_cache(self):
        if os.path.exists(self.EMAIL_CACHE_FILE):
            with open(self.EMAIL_CACHE_FILE, "r", encoding="utf-8") as f:
                try:
                    return json.load(f)
                except Exception:
                    return []
        return []

    def save_email_cache(self, emails):
        with open(self.EMAIL_CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump(emails, f, indent=2)
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

    def list_emails(self, mailbox="INBOX", limit=None, use_cache=True):
        """List emails from the mailbox. Returns a list of dicts with 'from', 'date', 'subject', 'uid'. Only fetches headers for speed. Uses cache if available."""
        if use_cache:
            cached = self.load_email_cache()
        else:
            cached = []
        if not self.imap:
            raise RuntimeError("IMAP connection not established.")
        self.imap.select(mailbox)
        typ, data = self.imap.search(None, "ALL")
        if typ != "OK":
            return []
        uids = data[0].split()
        if limit is not None:
            uids = uids[-limit:]
        # Find the highest UID in cache
        cached_uids = set(e["uid"] for e in cached)
        new_uids = [uid for uid in reversed(uids) if (uid.decode() if isinstance(uid, bytes) else str(uid)) not in cached_uids]
        emails = list(cached)  # Start with cached emails
        # Only fetch new headers
        for uid in new_uids:
            typ, msg_data = self.imap.fetch(uid, '(BODY.PEEK[HEADER.FIELDS (FROM SUBJECT DATE)])')
            if typ != "OK":
                continue
            headers = email.message_from_bytes(msg_data[0][1])
            emails.insert(0, {  # insert at front to keep order
                "from": headers.get("From", ""),
                "date": headers.get("Date", ""),
                "subject": headers.get("Subject", ""),
                "uid": uid.decode() if isinstance(uid, bytes) else str(uid)
            })
        # If limit is set, trim to limit
        if limit is not None:
            emails = emails[:limit]
        # Save updated cache
        if use_cache:
            self.save_email_cache(emails)
        return emails


    def _fetch_email(self, uid):
        typ, msg_data = self.imap.fetch(uid, "(RFC822)")
        if typ != "OK":
            return None
        return email.message_from_bytes(msg_data[0][1])

# Alias for backward compatibility with tests
GmailClient = GmailConnector