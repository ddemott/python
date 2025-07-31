import imaplib
import smtplib
import email
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.header import decode_header
from datetime import datetime

class EmailActions:
    def __init__(self, imap_server, smtp_server, smtp_port, username, password):
        self.imap_server = imap_server
        self.smtp_server = smtp_server
        self.smtp_port = smtp_port
        self.username = username
        self.password = password

    def bulk_delete_emails(self, email_ids):
        deleted = 0
        with imaplib.IMAP4_SSL(self.imap_server) as mail:
            mail.login(self.username, self.password)
            mail.select('inbox')
            for email_id in email_ids:
                email_id_bytes = str(email_id).encode()
                mail.store(email_id_bytes, '+FLAGS', '\Deleted')
                deleted += 1
            mail.expunge()
        return deleted

    def bulk_move_emails(self, email_ids, target_folder):
        moved = 0
        with imaplib.IMAP4_SSL(self.imap_server) as mail:
            mail.login(self.username, self.password)
            mail.select('inbox')
            for email_id in email_ids:
                email_id_bytes = str(email_id).encode()
                mail.copy(email_id_bytes, target_folder)
                mail.store(email_id_bytes, '+FLAGS', '\Deleted')
                moved += 1
            mail.expunge()
        return moved

    def create_email(self, to_addr, subject, body):
        msg = MIMEMultipart()
        msg['From'] = self.username
        msg['To'] = to_addr
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain', 'utf-8'))
        return msg

    def send_email(self, to_addr, subject, body):
        msg = self.create_email(to_addr, subject, body)
        with smtplib.SMTP(self.smtp_server, self.smtp_port, timeout=10) as server:
            server.ehlo()
            if server.has_extn('STARTTLS'):
                server.starttls()
                server.ehlo()
            server.login(self.username, self.password)
            server.send_message(msg)
        return True

    def mark_email_unread(self, email_id):
        with imaplib.IMAP4_SSL(self.imap_server) as mail:
            mail.login(self.username, self.password)
            mail.select('inbox')
            email_id_bytes = str(email_id).encode()
            mail.store(email_id_bytes, '-FLAGS', '\Seen')
        return True

    def mark_email_read(self, email_id):
        with imaplib.IMAP4_SSL(self.imap_server) as mail:
            mail.login(self.username, self.password)
            mail.select('inbox')
            email_id_bytes = str(email_id).encode()
            mail.store(email_id_bytes, '+FLAGS', '\Seen')
        return True

    def mark_email_important(self, email_id):
        with imaplib.IMAP4_SSL(self.imap_server) as mail:
            mail.login(self.username, self.password)
            mail.select('inbox')
            email_id_bytes = str(email_id).encode()
            mail.store(email_id_bytes, '+FLAGS', '\Flagged')
        return True

    def mark_email_unimportant(self, email_id):
        with imaplib.IMAP4_SSL(self.imap_server) as mail:
            mail.login(self.username, self.password)
            mail.select('inbox')
            email_id_bytes = str(email_id).encode()
            mail.store(email_id_bytes, '-FLAGS', '\Flagged')
        return True
