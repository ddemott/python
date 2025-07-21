import re
import json
import os
from gmail_client import GmailConnector

FILTERS_FILE = "filters.json"
JOBS_FILE = "jobs.json"

class EmailManager:
    def __init__(self):
        self.client = GmailConnector()
        self.emails_data = []
        self._emails_data_buffer = None

    def delete_emails_by_uid_list(self, uid_list, permanent=False):
        if not uid_list:
            print("[DEBUG] No UIDs provided for deletion.")
            return
        self.client.load_credentials()
        self.client.connect_imap()
        trash_mailbox = '[Gmail]/Trash'
        def to_ascii(uid):
            # Always convert to string, skip empty/None
            if uid is None:
                return None
            if isinstance(uid, bytes):
                return uid.decode('ascii')
            return str(uid)
        # Print all UIDs received for deletion
        print(f"[DEBUG] UIDs received for deletion: {uid_list}")
        try:
            # Always select INBOX before any IMAP commands
            sel_result, sel_data = self.client.imap.select('INBOX')
            print(f"[DEBUG] SELECT INBOX before delete: {sel_result}, {sel_data}")
            # Convert all UIDs to strings and filter out invalid/empty ones
            uid_str_list = []
            for uid in uid_list:
                uid_str = to_ascii(uid)
                # Only accept non-empty, digit-only UIDs (IMAP expects numbers)
                if uid_str and uid_str.isdigit():
                    uid_str_list.append(uid_str)
                else:
                    print(f"[WARNING] Skipping invalid UID: {uid} -> {uid_str}")
            print(f"[DEBUG] UIDs sent to IMAP: {uid_str_list}")
            def debug_imap_command(cmd, *args):
                print(f"[IMAP-CMD] {cmd} args: {args}")
            if permanent:
                print(f"[DEBUG] Permanent delete: moving to Trash, then expunging in Trash.")
                # Move to Trash
                for uid_str in uid_str_list:
                    debug_imap_command('COPY', uid_str, trash_mailbox)
                    result, data = self.client.imap.uid('COPY', uid_str, trash_mailbox)
                    print(f"[DEBUG] COPY UID {uid_str} to Trash: {result}, {data}")
                    if result != 'OK':
                        raise Exception(f"IMAP UID COPY to Trash failed for UID {uid_str}: {data}")
                # Mark as deleted in INBOX
                for uid_str in uid_str_list:
                    debug_imap_command('STORE', uid_str, '+FLAGS', r'(\\Deleted)')
                    result, data = self.client.imap.uid('STORE', uid_str, '+FLAGS', r'(\\Deleted)')
                    print(f"[DEBUG] STORE (INBOX) UID {uid_str}: {result}, {data}")
                debug_imap_command('EXPUNGE')
                expunge_result, expunge_data = self.client.imap.expunge()
                print(f"[DEBUG] EXPUNGE INBOX: {expunge_result}, {expunge_data}")
                # Now expunge all in Trash
                sel_result, sel_data = self.client.imap.select(trash_mailbox)
                print(f"[DEBUG] SELECT Trash: {sel_result}, {sel_data}")
                for uid_str in uid_str_list:
                    debug_imap_command('STORE', uid_str, '+FLAGS', r'(\\Deleted)')
                    result, data = self.client.imap.uid('STORE', uid_str, '+FLAGS', r'(\\Deleted)')
                    print(f"[DEBUG] STORE (Trash) UID {uid_str}: {result}, {data}")
                debug_imap_command('EXPUNGE')
                expunge_result, expunge_data = self.client.imap.expunge()
                print(f"[DEBUG] EXPUNGE Trash: {expunge_result}, {expunge_data}")
            else:
                print(f"[DEBUG] Standard delete: moving to Trash only.")
                for uid_str in uid_str_list:
                    debug_imap_command('COPY', uid_str, trash_mailbox)
                    result, data = self.client.imap.uid('COPY', uid_str, trash_mailbox)
                    print(f"[DEBUG] COPY UID {uid_str} to Trash: {result}, {data}")
                    if result != 'OK':
                        raise Exception(f"IMAP UID COPY to Trash failed for UID {uid_str}: {data}")
                for uid_str in uid_str_list:  
                    result, data = self.client.imap.uid('STORE', uid_str, '+FLAGS', r'(\Deleted)')
                expunge_result, expunge_data = self.client.imap.expunge()
                print(f"[DEBUG] EXPUNGE INBOX: {expunge_result}, {expunge_data}")
        except Exception as e:
            print(f"[ERROR] Exception during delete_emails_by_uid_list: {e}")
            raise
        finally:
            self.client.logout()
        # Remove from in-memory lists
        self.emails_data = [e for e in self.emails_data if to_ascii(e.get('uid')) not in [to_ascii(u) for u in uid_list]]
        if hasattr(self, '_emails_data_buffer') and self._emails_data_buffer is not None:
            self._emails_data_buffer = [e for e in self._emails_data_buffer if to_ascii(e.get('uid')) not in [to_ascii(u) for u in uid_list]]
        else:
            self._emails_data_buffer = [e for e in self.emails_data]
        print(f"[DEBUG] After deletion, emails_data: {self.emails_data}")
        print(f"[DEBUG] After deletion, _emails_data_buffer: {self._emails_data_buffer}")

    @staticmethod
    def email_matches_regex(email, regex):
        if not regex:
            return True
        from_field = str(email.get('from', ''))
        subject_field = str(email.get('subject', ''))
        try:
            from email.header import decode_header
            def decode_str(s):
                parts = decode_header(s)
                return ''.join([t[0].decode(t[1] or 'utf-8') if isinstance(t[0], bytes) else t[0] for t in parts])
            subject_field_decoded = decode_str(subject_field)
        except Exception:
            subject_field_decoded = subject_field
        email_match = re.search(r'<([^>]+)>', from_field)
        email_addr = email_match.group(1) if email_match else from_field
        display_name = from_field.split('<')[0].strip() if '<' in from_field else from_field
        for field in [from_field, email_addr, display_name, subject_field_decoded]:
            if regex.lower() in field.lower():
                return True
        try:
            pattern = re.compile(regex, re.IGNORECASE)
        except re.error:
            return False
        for field in [from_field, email_addr, display_name, subject_field_decoded]:
            if pattern.search(field):
                return True
        return False

    def load_filters(self):
        if os.path.exists(FILTERS_FILE):
            with open(FILTERS_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        return []

    def save_filters(self, filters):
        with open(FILTERS_FILE, "w", encoding="utf-8") as f:
            json.dump(filters, f, indent=2)

    def load_jobs(self):
        if os.path.exists(JOBS_FILE):
            with open(JOBS_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        return []

    def save_jobs(self, jobs):
        with open(JOBS_FILE, "w", encoding="utf-8") as f:
            json.dump(jobs, f, indent=2)
