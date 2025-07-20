import pytest
from unittest.mock import MagicMock, patch
import sys
import types

# Import EmailViewer and FilterDialog from pyside_email_viewer.py
import importlib.util
import os

spec = importlib.util.spec_from_file_location("pyside_email_viewer", os.path.abspath("pyside_email_viewer.py"))
pyside_email_viewer = importlib.util.module_from_spec(spec)
sys.modules["pyside_email_viewer"] = pyside_email_viewer
spec.loader.exec_module(pyside_email_viewer)

EmailViewer = pyside_email_viewer.EmailViewer
FilterDialog = pyside_email_viewer.FilterDialog

class DummyParent:
    def __init__(self, emails_data):
        self.emails_data = emails_data
        self._emails_data_buffer = list(emails_data)
        self.deleted_uids = []
    def email_matches_regex(self, email, regex):
        return EmailViewer.email_matches_regex(email, regex)
    def delete_emails_by_uid_list(self, uid_list):
        self.deleted_uids.extend(uid_list)
        self.emails_data = [e for e in self.emails_data if e.get('uid') not in uid_list]
    def apply_filter_to_emails(self, regex):
        self.filtered = [e for e in self.emails_data if self.email_matches_regex(e, regex)]

@pytest.fixture
def sample_emails():
    return [
        {"uid": "1", "from": "alice@somedomain.com", "subject": "Hello"},
        {"uid": "2", "from": "bob@other.com", "subject": "Hi"},
        {"uid": "3", "from": "carol@somedomain.com", "subject": "Re: Hello"},
    ]

def test_email_matches_regex(sample_emails):
    # Test substring and regex matching
    assert EmailViewer.email_matches_regex(sample_emails[0], "alice")
    assert EmailViewer.email_matches_regex(sample_emails[0], "somedomain.com")
    assert EmailViewer.email_matches_regex(sample_emails[0], r"alice@.*domain.com")
    assert not EmailViewer.email_matches_regex(sample_emails[1], "somedomain.com")
    assert EmailViewer.email_matches_regex(sample_emails[2], "Re: Hello")

def test_filtering(sample_emails):
    parent = DummyParent(sample_emails)
    # Simulate filtering for somedomain.com
    parent.apply_filter_to_emails("somedomain.com")
    assert len(parent.filtered) == 2
    assert all("somedomain.com" in e["from"] for e in parent.filtered)
    # Simulate filtering for bob
    parent.apply_filter_to_emails("bob")
    assert len(parent.filtered) == 1
    assert parent.filtered[0]["from"] == "bob@other.com"

def test_delete_emails_by_uid_list(sample_emails):
    parent = DummyParent(sample_emails)
    parent.delete_emails_by_uid_list(["1", "3"])
    assert len(parent.emails_data) == 1
    assert parent.emails_data[0]["uid"] == "2"
    assert set(parent.deleted_uids) == {"1", "3"}

def test_execute_job_delete(monkeypatch, sample_emails):
    # Prepare a dummy parent and FilterDialog
    parent = DummyParent(sample_emails)
    # Patch QMessageBox to avoid GUI
    monkeypatch.setattr(pyside_email_viewer, "QMessageBox", MagicMock())
    # Patch FilterDialog.load_jobs to return a delete job
    job = {"name": "somedomain.com", "filter": "somedomain.com", "action": "Delete"}
    class DummyFilterDialog(FilterDialog):
        def __init__(self, parent):
            # Don't call QDialog.__init__
            self.parent_ = parent
            self.job_list = MagicMock()
            self.job_list.selectedItems = lambda: [MagicMock(text=lambda: "somedomain.com:Delete")]
        def parent(self):
            return self.parent_
        def load_jobs(self):
            return [job]
    dlg = DummyFilterDialog(parent)
    # Add required methods to parent
    parent.delete_emails_by_uid_list = parent.delete_emails_by_uid_list
    parent.email_matches_regex = parent.email_matches_regex
    parent.emails_data = parent.emails_data
    # Execute the job
    dlg.execute_selected_job()
    # Should have deleted emails with somedomain.com
    assert set(parent.deleted_uids) == {"1", "3"}
    assert len(parent.emails_data) == 1
    assert parent.emails_data[0]["uid"] == "2"
