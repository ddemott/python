import os
import json
import os
import json
import time
import sys
from PySide6.QtWidgets import QApplication

# Ensure project root is in sys.path for imports
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)
from pyside_email_viewer import EmailViewer

JOBS_FILE = os.path.join(PROJECT_ROOT, 'jobs.json')

def test_delete_inspiring_quotes_emails():
    # Start QApplication for PySide6 widgets (headless)
    app = QApplication.instance() or QApplication(sys.argv)
    # Load the job definition for inspiringquotes.com Filter:Delete
    with open(JOBS_FILE, 'r', encoding='utf-8') as f:
        jobs = json.load(f)
    job = next((j for j in jobs if j['name'] == 'inspiringquotes.com Filter' and j['action'] == 'Delete'), None)
    assert job is not None, 'Job inspiringquotes.com Filter:Delete not found in jobs.json'
    regex = job.get('filter', '')
    assert regex, 'No filter found in inspiringquotes.com Filter:Delete job'

    viewer = EmailViewer()
    viewer.load_emails()
    emails_before = list(viewer.emails_data)
    matching_emails = [e for e in emails_before if viewer.email_matches_regex(e, regex)]
    print(f"[TEST] Found {len(matching_emails)} Inspiring Quotes emails to delete.")
    if not matching_emails:
        print("[TEST] No Inspiring Quotes emails found. Test passes trivially.")
        return
    uids = [e['uid'] for e in matching_emails if e.get('uid')]
    # Permanently delete matching emails
    viewer.delete_emails_by_uid_list(uids, permanent=True)
    # Wait a bit for IMAP to sync
    time.sleep(5)
    # Reload emails
    viewer.load_emails()
    emails_after = list(viewer.emails_data)
    # Check that none of the deleted emails remain
    remaining = [e for e in emails_after if viewer.email_matches_regex(e, regex)]
    assert not remaining, f"Some Inspiring Quotes emails still remain: {remaining}"
    print("[TEST] All Inspiring Quotes emails deleted successfully.")

if __name__ == "__main__":
    test_delete_inspiring_quotes_emails()
    print("[TEST] All Inspiring Quotes emails deleted successfully.")

if __name__ == "__main__":
    test_delete_inspiring_quotes_emails()
