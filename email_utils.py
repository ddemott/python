import imaplib
import smtplib
import email
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.header import decode_header
from datetime import datetime

class EmailUtils:
    @staticmethod
    def connect_imap(server, username, password):
        mail = imaplib.IMAP4_SSL(server)
        mail.login(username, password)
        return mail

    @staticmethod
    def connect_smtp(server, port, username, password):
        smtp = smtplib.SMTP(server, port, timeout=10)
        smtp.ehlo()
        if smtp.has_extn('STARTTLS'):
            smtp.starttls()
            smtp.ehlo()
        smtp.login(username, password)
        return smtp

    @staticmethod
    def parse_email_headers(raw_email):
        msg = email.message_from_bytes(raw_email)
        # Decode subject
        subject = msg.get("Subject", "No Subject")
        try:
            subject = "".join(
                part.decode(enc or "utf-8", errors="replace") if isinstance(part, bytes) else part
                for part, enc in decode_header(subject)
            )
        except Exception:
            pass
        # Get sender
        from_addr = msg.get("From", "Unknown")
        # Parse date
        date_str = msg.get("Date", "")
        date_formatted = "Unknown"
        try:
            date_obj = email.utils.parsedate_tz(date_str)
            if date_obj:
                timestamp = email.utils.mktime_tz(date_obj)
                date_formatted = datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M")
        except Exception:
            pass
        return subject, from_addr, date_formatted

    @staticmethod
    def create_email_message(from_addr, to_addr, subject, body):
        msg = MIMEMultipart()
        msg['From'] = from_addr
        msg['To'] = to_addr
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain', 'utf-8'))
        return msg

    @staticmethod
    def load_all_emails(mail, mailbox="INBOX"):
        """
        Loads all emails from the specified mailbox using an IMAP connection.
        Returns a list of tuples: (email_id, subject, from_addr, date_formatted)
        """
        mail.select(mailbox)
        result, data = mail.search(None, "ALL")
        if result != "OK":
            return []
        email_ids = data[0].split()
        emails = []
        for eid in email_ids:
            res, msg_data = mail.fetch(eid, "(RFC822)")
            if res != "OK":
                continue
            raw_email = msg_data[0][1]
            subject, from_addr, date_formatted = EmailUtils.parse_email_headers(raw_email)
            emails.append((eid.decode(), subject, from_addr, date_formatted))
        return emails

