import unittest
from filter_manager import FilterManager

class TestFilterManager(unittest.TestCase):
    def setUp(self):
        self.app_mock = None  # Mock or create a dummy app instance
        self.filter_manager = FilterManager(self.app_mock)

    def test_apply_filter(self):
        """Test the apply_filter method."""
        self.app_mock = type("AppMock", (), {})()
        self.app_mock.filter_field = type("FieldMock", (), {"get": lambda: "Subject"})()
        self.app_mock.filter_entry = type("EntryMock", (), {"get": lambda: "Test"})()
        self.app_mock.all_emails = [
            {"Subject": "Test email 1", "From": "user1@example.com"},
            {"Subject": "Another email", "From": "user2@example.com"},
            {"Subject": "Test email 2", "From": "user3@example.com"}
        ]
        self.app_mock.filtered_emails = []  # Initialize the attribute
        self.app_mock.display_emails = lambda emails: setattr(self.app_mock, "filtered_emails", emails)
        self.app_mock.set_status = lambda message, color: setattr(self.app_mock, "status", (message, color))

        self.filter_manager = FilterManager(self.app_mock)

        # Debug prints to inspect the state of filtered_emails
        print("Before apply_filter: filtered_emails =", self.app_mock.filtered_emails)
        self.filter_manager.apply_filter()
        print("After apply_filter: filtered_emails =", self.app_mock.filtered_emails)

        # Assertions
        self.assertEqual(len(self.app_mock.filtered_emails), 2)
        self.assertEqual(self.app_mock.status, ("Filter applied: 2 emails found.", "green"))

        # Explicitly print debug information after applying the filter
        print(f"Filtered Emails: {self.app_mock.filtered_emails}")
        print(f"Status: {self.app_mock.status}")

        # Log debug information to a file
        with open("debug_log.txt", "w") as log_file:
            log_file.write(f"Filtered Emails: {self.app_mock.filtered_emails}\n")
            log_file.write(f"Status: {self.app_mock.status}\n")

    def test_clear_filter(self):
        # Test logic for clear_filter
        pass

    def test_show_regex_help(self):
        # Test logic for show_regex_help
        pass

if __name__ == "__main__":
    unittest.main()
