import json
import imaplib
from typing import Optional


class GmailConnector:
    """Simple connector to Gmail using IMAP and app password."""

    def __init__(self, credentials_path: str = "credentials.json") -> None:
        self.credentials_path = credentials_path
        self.email: Optional[str] = None
        self.password: Optional[str] = None
        self.imap: Optional[imaplib.IMAP4_SSL] = None

    def load_credentials(self) -> None:
        """Load email and app password from a JSON file."""
        with open(self.credentials_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        self.email = data.get("email")
        self.password = data.get("app_password")

    def connect(self) -> None:
        """Connect to Gmail via IMAP using loaded credentials."""
        if not self.email or not self.password:
            raise ValueError("Credentials not loaded. Call load_credentials first.")
        self.imap = imaplib.IMAP4_SSL("imap.gmail.com")
        self.imap.login(self.email, self.password)

    def logout(self) -> None:
        """Logout and close IMAP connection."""
        if self.imap:
            try:
                self.imap.logout()
            finally:
                self.imap = None


if __name__ == "__main__":
    connector = GmailConnector()
    connector.load_credentials()
    try:
        connector.connect()
        print("Connected successfully.")
    finally:
        connector.logout()
        print("Logged out.")
