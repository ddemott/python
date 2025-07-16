
import sys
from PySide6.QtWidgets import QApplication, QWidget, QVBoxLayout, QPushButton, QListWidget, QLabel, QAbstractItemView
from gmail_client import GmailClient

class EmailViewer(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Gmail Email Viewer")
        self.resize(600, 400)
        layout = QVBoxLayout()

        self.status_label = QLabel("Click 'Load Emails' to fetch emails.")
        layout.addWidget(self.status_label)

        self.load_button = QPushButton("Load Emails")
        self.load_button.clicked.connect(self.load_emails)
        layout.addWidget(self.load_button)


        self.email_list = QListWidget()
        self.email_list.setSelectionMode(QAbstractItemView.SingleSelection)
        self.email_list.itemDoubleClicked.connect(self.show_email_in_browser)
        layout.addWidget(self.email_list)

        self.setLayout(layout)
        self.client = None
        self.emails_data = []  # Store full email data

    def load_emails(self):
        self.status_label.setText("Loading emails...")
        QApplication.processEvents()
        try:
            self.client = GmailClient()
            self.client.load_credentials()
            self.client.connect_imap()
            emails = self.client.list_emails()
            self.email_list.clear()
            self.emails_data = []
            for email in emails:
                item_text = f"From: {email['from']} | Subject: {email['subject']}"
                self.email_list.addItem(item_text)
                self.emails_data.append(email)  # Store for later use
            self.status_label.setText(f"Loaded {len(emails)} emails.")
        except Exception as e:
            self.status_label.setText(f"Error: {e}")
        finally:
            if self.client:
                self.client.logout()

    def show_email_in_browser(self, item):
        idx = self.email_list.row(item)
        if idx < 0 or idx >= len(self.emails_data):
            return
        email_info = self.emails_data[idx]
        # Fetch full email content
        try:
            self.client = GmailClient()
            self.client.load_credentials()
            self.client.connect_imap()
            # Ensure mailbox is selected before fetching
            if hasattr(self.client, 'imap') and self.client.imap:
                self.client.imap.select('INBOX')
            # Get UID and fetch full message
            uid = email_info['uid'].encode()
            msg = self.client._fetch_email(uid)
            html_body = None
            if msg.is_multipart():
                for part in msg.walk():
                    if part.get_content_type() == "text/html":
                        html_body = part.get_payload(decode=True).decode(errors="ignore")
                        break
            else:
                if msg.get_content_type() == "text/html":
                    html_body = msg.get_payload(decode=True).decode(errors="ignore")
            if not html_body:
                html_body = "<pre>" + (msg.get_payload(decode=True).decode(errors="ignore") if msg.get_payload(decode=True) else "No HTML content.") + "</pre>"
            # Write to temp file and open in browser
            import tempfile, webbrowser
            with tempfile.NamedTemporaryFile(delete=False, suffix=".html", mode="w", encoding="utf-8") as f:
                f.write(html_body)
                temp_path = f.name
            webbrowser.open(temp_path)
        except Exception as e:
            self.status_label.setText(f"Error displaying email: {e}")
        finally:
            if self.client:
                self.client.logout()

def main():
    app = QApplication(sys.argv)
    viewer = EmailViewer()
    viewer.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
