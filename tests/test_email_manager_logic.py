import pytest
from unittest.mock import MagicMock
import sys
import types
import importlib.util
import os

# Dynamically import pyside_email_viewer.py as a module
spec = importlib.util.spec_from_file_location("pyside_email_viewer", os.path.abspath("pyside_email_viewer.py"))
pyside_email_viewer = importlib.util.module_from_spec(spec)
sys.modules["pyside_email_viewer"] = pyside_email_viewer
spec.loader.exec_module(pyside_email_viewer)

EmailViewer = pyside_email_viewer.EmailViewer

# --- Pure logic helpers (no GUI) ---
class DummyParent:
    def __init__(self, emails_data):
        self.emails_data = emails_data
        self._emails_data_buffer = list(emails_data)
        self.deleted_uids = []
        self.filtered = []
    def email_matches_regex(self, email, regex):
        return EmailViewer.email_matches_regex(email, regex)
    def delete_emails_by_uid_list(self, uid_list):
        self.deleted_uids.extend(uid_list)
        self.emails_data = [e for e in self.emails_data if e.get('uid') not in uid_list]
    def apply_filter_to_emails(self, regex):
        self.filtered = [e for e in self.emails_data if self.email_matches_regex(e, regex)]

# --- Fixtures ---
@pytest.fixture
def sample_emails():
    return [
        {"uid": "1", "from": "alice@somedomain.com", "subject": "Hello"},
        {"uid": "2", "from": "bob@other.com", "subject": "Hi"},
        {"uid": "3", "from": "carol@somedomain.com", "subject": "Re: Hello"},
    ]

# --- Test filtering logic ---
def test_email_matches_regex(sample_emails):
    assert EmailViewer.email_matches_regex(sample_emails[0], "alice")
    assert EmailViewer.email_matches_regex(sample_emails[0], "somedomain.com")
    assert EmailViewer.email_matches_regex(sample_emails[0], r"alice@.*domain.com")
    assert not EmailViewer.email_matches_regex(sample_emails[1], "somedomain.com")
    assert EmailViewer.email_matches_regex(sample_emails[2], "Re: Hello")

def test_filtering(sample_emails):
    parent = DummyParent(sample_emails)
    parent.apply_filter_to_emails("somedomain.com")
    assert len(parent.filtered) == 2
    assert all("somedomain.com" in e["from"] for e in parent.filtered)
    parent.apply_filter_to_emails("bob")
    assert len(parent.filtered) == 1
    assert parent.filtered[0]["from"] == "bob@other.com"

# --- Test deletion logic ---
def test_delete_emails_by_uid_list(sample_emails):
    parent = DummyParent(sample_emails)
    parent.delete_emails_by_uid_list(["1", "3"])
    assert len(parent.emails_data) == 1
    assert parent.emails_data[0]["uid"] == "2"
    assert set(parent.deleted_uids) == {"1", "3"}

# --- Test job execution logic (no GUI) ---
def test_execute_job_delete(sample_emails):
    parent = DummyParent(sample_emails)
    # Simulate a job dict
    job = {"name": "somedomain.com", "filter": "somedomain.com", "action": "Delete"}
    # Simulate job execution logic (no GUI)
    regex = job["filter"]
    emails_to_delete = [email for email in parent.emails_data if parent.email_matches_regex(email, regex)]
    if emails_to_delete:
        uid_list = [e.get('uid') for e in emails_to_delete if e.get('uid')]
        parent.delete_emails_by_uid_list(uid_list)
    # Assert correct emails deleted
    assert set(parent.deleted_uids) == {"1", "3"}
    assert len(parent.emails_data) == 1
    assert parent.emails_data[0]["uid"] == "2"
