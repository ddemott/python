import unittest
from unittest.mock import patch, MagicMock
import re

# Example core functions to be tested (to be refactored from GUI)
def filter_emails(emails, pattern, field):
    regex = re.compile(pattern, re.IGNORECASE)
    filtered = []
    for email in emails:
        email_id, from_addr, subject, date_formatted = email
        match_found = False
        if field.lower() == 'from':
            match_found = regex.search(from_addr)
        elif field.lower() == 'subject':
            match_found = regex.search(subject)
        else:
            match_found = regex.search(from_addr) or regex.search(subject)
        if match_found:
            filtered.append(email)
    return filtered

def save_rules(rules, filename):
    import json
    with open(filename, 'w') as f:
        json.dump(rules, f, indent=2)

def load_rules(filename):
    import json
    with open(filename, 'r') as f:
        return json.load(f)

def delete_email(email_id, username, password):
    import imaplib
    try:
        with imaplib.IMAP4_SSL('imap.gmail.com') as mail:
            mail.login(username, password)
            mail.select('inbox')
            email_id_bytes = str(email_id).encode()
            mail.store(email_id_bytes, '+FLAGS', '\\Deleted')
            mail.expunge()
        return True
    except Exception:
        return False

def bulk_delete_emails(email_ids, username, password):
    import imaplib
    deleted = 0
    try:
        with imaplib.IMAP4_SSL('imap.gmail.com') as mail:
            mail.login(username, password)
            mail.select('inbox')
            for email_id in email_ids:
                email_id_bytes = str(email_id).encode()
                mail.store(email_id_bytes, '+FLAGS', '\\Deleted')
                deleted += 1
            mail.expunge()
        return deleted
    except Exception:
        return deleted

class TestCoreFunctionality(unittest.TestCase):
    def setUp(self):
        self.emails = [
            ('1', 'alice@gmail.com', 'Hello World', '2025-07-27 10:00'),
            ('2', 'bob@yahoo.com', 'Test Subject', '2025-07-27 11:00'),
            ('3', 'carol@gmail.com', 'Spam Offer', '2025-07-27 12:00'),
        ]
        self.rules = [
            {'name': 'Gmail', 'pattern': '@gmail.com', 'field': 'from', 'created': '2025-07-27 10:00', 'sample_emails': 2}
        ]

    def test_filter_emails_by_from(self):
        filtered = filter_emails(self.emails, '@gmail.com', 'From')
        self.assertEqual(len(filtered), 2)

    def test_filter_emails_by_subject(self):
        filtered = filter_emails(self.emails, 'Spam', 'Subject')
        self.assertEqual(len(filtered), 1)
        self.assertEqual(filtered[0][2], 'Spam Offer')

    @patch('builtins.open')
    @patch('json.dump')
    def test_save_rules(self, mock_json_dump, mock_open):
        save_rules(self.rules, 'rules.json')
        mock_open.assert_called_once_with('rules.json', 'w')
        mock_json_dump.assert_called_once()

    @patch('builtins.open')
    @patch('json.load')
    def test_load_rules(self, mock_json_load, mock_open):
        mock_json_load.return_value = self.rules
        mock_open.return_value.__enter__.return_value = MagicMock()
        loaded = load_rules('rules.json')
        self.assertEqual(loaded[0]['name'], 'Gmail')

    @patch('imaplib.IMAP4_SSL')
    def test_delete_email(self, mock_imap):
        mock_mail = MagicMock()
        mock_imap.return_value.__enter__.return_value = mock_mail
        result = delete_email('1', 'user', 'pass')
        self.assertTrue(result)
        mock_mail.login.assert_called_once()
        mock_mail.store.assert_called_once()

    @patch('imaplib.IMAP4_SSL')
    def test_bulk_delete_emails(self, mock_imap):
        mock_mail = MagicMock()
        mock_imap.return_value.__enter__.return_value = mock_mail
        deleted = bulk_delete_emails(['1', '2'], 'user', 'pass')
        self.assertEqual(deleted, 2)
        mock_mail.login.assert_called_once()
        self.assertEqual(mock_mail.store.call_count, 2)

if __name__ == '__main__':
    unittest.main()
