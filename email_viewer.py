
import sys
from PySide6.QtWidgets import QApplication, QWidget, QVBoxLayout, QPushButton, QListWidget, QLabel, QAbstractItemView
from email_manager import EmailManager


# New EmailManager class for business logic
class EmailManager:
    def __init__(self):
        from gmail_client import GmailConnector
        self.client = GmailConnector()

    def load_emails(self):
        self.client.load_credentials()
        self.client.connect_imap()
        emails = self.client.list_emails(limit=1000)
        self.client.logout()
        return emails

    def fetch_email_html(self, email_info):
        self.client.load_credentials()
        self.client.connect_imap()
        if hasattr(self.client, 'imap') and self.client.imap:
            self.client.imap.select('INBOX')
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
        self.client.logout()
        return html_body

# GUI class uses EmailManager for all business logic
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
        self.manager = EmailManager()
        self.emails_data = []  # Store full email data

    def load_emails(self):
        self.status_label.setText("Loading emails...")
        QApplication.processEvents()
        try:
            emails = self.manager.load_emails()
            self.email_list.clear()
            self.emails_data = []
            for email in emails:
                item_text = f"From: {email['from']} | Subject: {email['subject']}"
                self.email_list.addItem(item_text)
                self.emails_data.append(email)  # Store for later use
            self.status_label.setText(f"Loaded {len(emails)} emails.")
        except Exception as e:
            self.status_label.setText(f"Error: {e}")

    def show_email_in_browser(self, item):
        idx = self.email_list.row(item)
        if idx < 0 or idx >= len(self.emails_data):
            return
        email_info = self.emails_data[idx]
        try:
            html_body = self.manager.fetch_email_html(email_info)
            import tempfile, webbrowser
            with tempfile.NamedTemporaryFile(delete=False, suffix=".html", mode="w", encoding="utf-8") as f:
                f.write(html_body)
                temp_path = f.name
            webbrowser.open(temp_path)
        except Exception as e:
            self.status_label.setText(f"Error displaying email: {e}")

def main():
    app = QApplication(sys.argv)
    viewer = EmailViewer()
    viewer.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
