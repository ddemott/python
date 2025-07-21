import unittest
from email_manager import EmailManager

class TestEmailManager(unittest.TestCase):
    def setUp(self):
        self.manager = EmailManager()
        self.sample_emails = [
            {'uid': '1', 'from': 'Alice <alice@example.com>', 'subject': 'Hello World', 'date': '2025-07-20 10:00'},
            {'uid': '2', 'from': 'Bob <bob@inspiringquotes.com>', 'subject': 'Inspiring Quotes', 'date': '2025-07-19 09:00'},
            {'uid': '3', 'from': 'Carol <carol@other.com>', 'subject': 'Other Stuff', 'date': '2025-07-18 08:00'},
        ]

    def test_email_matches_regex_substring(self):
        email = self.sample_emails[1]
        self.assertTrue(self.manager.email_matches_regex(email, 'inspiringquotes'))
        self.assertTrue(self.manager.email_matches_regex(email, 'Inspiring Quotes'))
        self.assertFalse(self.manager.email_matches_regex(email, 'notfound'))

    def test_email_matches_regex_regex(self):
        email = self.sample_emails[0]
        self.assertTrue(self.manager.email_matches_regex(email, r'alice@.*\.com'))
        self.assertFalse(self.manager.email_matches_regex(email, r'bob@.*\.com'))

    def test_filter_emails(self):
        filtered = self.manager.filter_emails(self.sample_emails, 'inspiringquotes')
        self.assertEqual(len(filtered), 1)
        self.assertEqual(filtered[0]['uid'], '2')
        filtered = self.manager.filter_emails(self.sample_emails, 'other.com')
        self.assertEqual(len(filtered), 1)
        self.assertEqual(filtered[0]['uid'], '3')
        filtered = self.manager.filter_emails(self.sample_emails, 'notfound')
        self.assertEqual(len(filtered), 0)

    def test_restore_emails(self):
        buffer = self.sample_emails.copy()
        restored = self.manager.restore_emails(buffer)
        self.assertEqual(restored, buffer)
        restored = self.manager.restore_emails(None)
        self.assertEqual(restored, [])

    # Note: delete_emails_by_uid_list interacts with Gmail IMAP, so we only test the interface here
    def test_delete_emails_by_uid_list_interface(self):
        # Should not raise error for empty list
        try:
            self.manager.delete_emails_by_uid_list([], permanent=False)
        except Exception as e:
            self.fail(f"delete_emails_by_uid_list raised Exception unexpectedly: {e}")

if __name__ == '__main__':
    unittest.main()
