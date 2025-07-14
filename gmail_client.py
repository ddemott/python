import json
import re
import imaplib
import smtplib
import email
from email.message import EmailMessage
from typing import List, Optional, Dict


class GmailConnector:
    """Simple connector to Gmail using IMAP and app password."""

    def __init__(self, credentials_path: str = "credentials.json") -> None:
        self.credentials_path = credentials_path
        self.email: Optional[str] = None
        self.password: Optional[str] = None
        self.imap: Optional[imaplib.IMAP4_SSL] = None
        self.smtp: Optional[smtplib.SMTP_SSL] = None

    def load_credentials(self) -> None:
        """Load email and app password from a JSON file."""
        with open(self.credentials_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        self.email = data.get("email")
        self.password = data.get("app_password")

    def connect_imap(self) -> None:
        """Connect to Gmail via IMAP using loaded credentials."""
        if not self.email or not self.password:
            raise ValueError("Credentials not loaded. Call load_credentials first.")
        self.imap = imaplib.IMAP4_SSL("imap.gmail.com")
        self.imap.login(self.email, self.password)

    def connect_smtp(self) -> None:
        """Connect to Gmail via SMTP using loaded credentials."""
        if not self.email or not self.password:
            raise ValueError("Credentials not loaded. Call load_credentials first.")
        self.smtp = smtplib.SMTP_SSL("smtp.gmail.com", 465)
        self.smtp.login(self.email, self.password)

    def logout(self) -> None:
        """Logout and close IMAP/SMTP connections."""
        if self.imap:
            try:
                self.imap.logout()
            finally:
                self.imap = None
        if self.smtp:
            try:
                self.smtp.quit()
            finally:
                self.smtp = None


class GmailClient(GmailConnector):
    """Gmail client that can read, send, and manage messages."""

    def send_email(self, to_addr: str, subject: str, body: str) -> None:
        """Compose and send an email via SMTP."""
        if not self.smtp:
            raise ValueError("SMTP connection not established.")
        msg = EmailMessage()
        msg["From"] = self.email
        msg["To"] = to_addr
        msg["Subject"] = subject
        msg.set_content(body)
        self.smtp.send_message(msg)

    # Utility methods for IMAP
    def _select_folder(self, folder: str = "INBOX") -> None:
        if not self.imap:
            raise ValueError("IMAP connection not established.")
        self.imap.select(folder)

    def _search(self, criteria: str = "ALL") -> List[bytes]:
        typ, data = self.imap.search(None, criteria)
        if typ != "OK" or not data:
            return []
        return data[0].split()

    def _fetch_email(self, uid: bytes) -> email.message.Message:
        typ, data = self.imap.fetch(uid, "(RFC822)")
        if typ != "OK":
            raise RuntimeError("Failed to fetch email %s" % uid.decode())
        return email.message_from_bytes(data[0][1])

    # Public methods
    def list_emails(self, folder: str = "INBOX", criteria: str = "ALL") -> List[Dict[str, str]]:
        """Return a list of emails with basic info (UID, From, Subject)."""
        self._select_folder(folder)
        uids = self._search(criteria)
        messages: List[Dict[str, str]] = []
        for uid in uids:
            msg = self._fetch_email(uid)
            messages.append({
                "uid": uid.decode(),
                "from": msg.get("From", ""),
                "subject": msg.get("Subject", ""),
            })
        return messages

    def apply_rules(self, rules: List[Dict[str, str]], folder: str = "INBOX") -> None:
        """Apply rules to messages in a folder."""
        self._select_folder(folder)
        uids = self._search("ALL")
        for uid in uids:
            msg = self._fetch_email(uid)
            subject = msg.get("Subject", "")
            body_parts = []
            if msg.is_multipart():
                for part in msg.walk():
                    if part.get_content_type() == "text/plain":
                        try:
                            body_parts.append(part.get_payload(decode=True).decode(errors="ignore"))
                        except Exception:
                            pass
            else:
                try:
                    body_parts.append(msg.get_payload(decode=True).decode(errors="ignore"))
                except Exception:
                    pass
            body = "\n".join(body_parts)
            for rule in rules:
                pattern = rule.get("pattern")
                field = rule.get("search_field", "subject")
                action = rule.get("action", "").upper()
                folder_name = rule.get("folder")
                if not pattern or not action:
                    continue
                target = subject if field == "subject" else body
                if not re.search(pattern, target, re.IGNORECASE):
                    continue
                self._apply_action(uid, action, folder_name)
                # Once a rule matches, stop applying other rules to this email
                break
        # Expunge deleted items if any
        self.imap.expunge()

    def _apply_action(self, uid: bytes, action: str, folder_name: Optional[str]) -> None:
        if action == "DELETE":
            self.imap.store(uid, "+FLAGS", "\\Deleted")
        elif action == "MARK_READ":
            self.imap.store(uid, "+FLAGS", "\\Seen")
        elif action == "MARK_UNREAD":
            self.imap.store(uid, "-FLAGS", "\\Seen")
        elif action == "MARK_IMPORTANT":
            self.imap.store(uid, "+X-GM-LABELS", "\\Important")
        elif action == "MOVE" and folder_name:
            # Copy to folder and mark as deleted from current
            self.imap.copy(uid, folder_name)
            self.imap.store(uid, "+FLAGS", "\\Deleted")


def load_rules(path: str = "rules.json") -> List[Dict[str, str]]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return []


def main() -> None:
    client = GmailClient()
    client.load_credentials()
    client.connect_imap()
    client.connect_smtp()

    rules = load_rules()
    if rules:
        client.apply_rules(rules)

    # Example sending function: disabled by default
    # client.send_email("recipient@example.com", "Test", "Hello from GmailClient")

    client.logout()


if __name__ == "__main__":
    main()
