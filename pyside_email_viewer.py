import sys
import json
import os
import re
from PySide6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QPushButton, QTableWidget, QTableWidgetItem,
    QLabel, QAbstractItemView, QDialog, QTextEdit, QLineEdit, QHBoxLayout, QListWidget,
    QListWidgetItem, QMessageBox, QComboBox, QInputDialog
)
from PySide6.QtCore import Qt, Signal
from email_manager import EmailManager

from gmail_client import GmailConnector as GmailClient

FILTERS_FILE = "filters.json"
RULES_FILE = "rules.json"

class FilterDialog(QDialog):
    def new_filter(self):
        self.name_edit.clear()
        self.action_combo.setCurrentIndex(0)
        self.rule_label.setText("Selected Filter: None (New)")
        self.editing_index = None
        new_label = "<New Filter>: "
        # Remove all existing temporary new filter items
        for i in reversed(range(self.filter_list.count())):
            if self.filter_list.item(i).text().startswith(new_label):
                self.filter_list.takeItem(i)
        # Optionally, refresh the filter list to remove any duplicate at the bottom
        self.refresh_filter_list()
        # Insert a new <New Filter> at the bottom
        new_item = QListWidgetItem(f"{new_label}")
        self.filter_list.addItem(new_item)
        self.filter_list.setCurrentItem(new_item)
    filter_applied = Signal(str)  # regex string

    def __init__(self, parent, selected_emails):
        super().__init__(parent)
        self.setWindowTitle("Filters")
        self.resize(1050, 450)  # 50% bigger than 700x300
        self.selected_emails = selected_emails
        self.filters = self.load_filters()
        self._original_filter_items = None  # For restoring filter list
        self.editing_index = None  # Track which filter is being edited
        self.init_ui()
        # Only generate a filter if 2 or more are selected
        if self.selected_emails and len(self.selected_emails) > 0:
            # Analyze the emails and generate a filter for each unique domain
            domains = set()
            for email in self.selected_emails:
                sender = email.get('from', '')
                match = re.search(r'@([A-Za-z0-9.-]+\.[A-Za-z]{2,})', sender)
                if match:
                    domains.add(match.group(1))
            if domains:
                # Remove any existing <New Filter> or Filter: at the top
                for i in reversed(range(self.filter_list.count())):
                    if self.filter_list.item(i).text().startswith("<New Filter>:") or self.filter_list.item(i).text().startswith("Filter: "):
                        self.filter_list.takeItem(i)
                # For each domain, create a filter with the correct name
                for domain in sorted(domains):
                    filter_name = f"{domain} Filter"
                    regex = domain
                    # Only update the UI fields, do not add to list or save
                    self.name_edit.setText(filter_name)
                    self.regex_edit.setText(regex)
                    self.editing_index = None
                    self.rule_label.setText(f"Selected Filter: {filter_name}")
            else:
                self.new_filter()
        else:
            self.new_filter()

        # Now that the filter list is fully initialized, save the original items
        self.update_original_filter_items()

    def update_original_filter_items(self):
        self._original_filter_items = [self.filter_list.item(i).text() for i in range(self.filter_list.count())]


    def init_ui(self):
        main_layout = QVBoxLayout()
        main_layout.addWidget(QLabel("Select a Filter to Edit:"))
        new_btn = QPushButton("New Filter")
        new_btn.clicked.connect(self.new_filter)
        main_layout.addWidget(new_btn)
        self.filter_list = QListWidget()
        self.filter_list.setDragDropMode(QListWidget.InternalMove)
        self.filter_list.setSelectionMode(QListWidget.ExtendedSelection)
        self.filter_list.setStyleSheet("QListWidget::item { font-family: monospace; font-size: 13px; min-height: 28px; } QListWidget::item:selected { background: #0078d7; color: white; }")
        self.filter_list.itemClicked.connect(self.load_filter_for_edit)
        self.refresh_filter_list()
        main_layout.addWidget(self.filter_list)

        name_row = QHBoxLayout()
        name_label = QLabel("Filter Name:")
        self.name_edit = QLineEdit()
        self.name_edit.setPlaceholderText("Enter filter name")
        name_row.addWidget(name_label)
        name_row.addWidget(self.name_edit)
        # Print the first email loaded for deep debug
        if self.selected_emails and len(self.selected_emails) > 0:
            print("[DEEPDEBUG] First email loaded (full dict):")
            print(json.dumps(self.selected_emails[0], indent=2))
            print(f"[DEEPDEBUG] Keys: {list(self.selected_emails[0].keys())}")
            for k, v in self.selected_emails[0].items():
                print(f"    {k}: {v}")
        main_layout.addLayout(name_row)

        regex_row = QHBoxLayout()
        regex_label = QLabel("Regex:")
        self.regex_edit = QLineEdit()
        self.regex_edit.setPlaceholderText("Enter filter regex")
        regex_row.addWidget(regex_label)
        regex_row.addWidget(self.regex_edit)
        main_layout.addLayout(regex_row)

        btn_layout = QHBoxLayout()
        self.test_btn = QPushButton("Apply Filter")
        self.clear_btn = QPushButton("Clear Filter")
        self.save_btn = QPushButton("Save Filter")
        self.edit_btn = QPushButton("Edit Filter")
        self.delete_btn = QPushButton("Delete Filter")
        btn_layout.addWidget(self.test_btn)
        btn_layout.addWidget(self.clear_btn)
        btn_layout.addWidget(self.save_btn)
        btn_layout.addWidget(self.edit_btn)
        btn_layout.addWidget(self.delete_btn)
        main_layout.addLayout(btn_layout)


        # --- New Action/Job Section ---
        action_job_row = QHBoxLayout()

        # Left: Action selection and Save Action button
        action_col = QVBoxLayout()
        action_label = QLabel("Select Action:")
        self.action_combo = QComboBox()
        self.action_combo.addItems(["Delete", "Move", "Mark Unread", "Mark Read", "Mark as Important", "Mark as Unimportant"])
        action_col.addWidget(action_label)
        action_col.addWidget(self.action_combo)
        self.save_action_btn = QPushButton("Save Action")
        self.execute_action_btn = QPushButton("Execute Action")
        self.delete_action_btn = QPushButton("Delete Action")
        action_col.addWidget(self.save_action_btn)
        action_col.addWidget(self.execute_action_btn)
        action_col.addWidget(self.delete_action_btn)
        action_col.addStretch()

        # Right: Job List
        job_col = QVBoxLayout()
        job_label = QLabel("Job List")
        job_col.addWidget(job_label)
        self.job_list = QListWidget()
        job_col.addWidget(self.job_list)
        job_col.addStretch()

        action_job_row.addLayout(action_col)
        action_job_row.addLayout(job_col)
        main_layout.addLayout(action_job_row)

        # --- Rule Builder Section ---
        self.rule_label = QLabel("Selected Filter: None")
        main_layout.addWidget(self.rule_label)

        self.setLayout(main_layout)

        self.test_btn.clicked.connect(self.test_filter)
        self.clear_btn.clicked.connect(self.clear_filter)
        self.save_btn.clicked.connect(self.save_filter)
        self.edit_btn.clicked.connect(self.edit_filter)
        self.delete_btn.clicked.connect(self.delete_filter)
        self.save_action_btn.clicked.connect(self.save_action_to_job)
        self.refresh_job_list()
        self.execute_action_btn.clicked.connect(self.execute_selected_job)
        self.delete_action_btn.clicked.connect(self.delete_selected_job)

    def edit_filter(self):
        """
        Open a dialog to edit all aspects of the selected filter (name, regex, action).
        """
        selected_items = self.filter_list.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "Edit Filter", "Please select a filter to edit.")
            return
        item = selected_items[0]
        name = item.text().split(":")[0]
        # Find the filter in self.filters
        for idx, f in enumerate(self.filters):
            if f["name"] == name:
                # Open a dialog for editing
                dlg = QDialog(self)
                dlg.setWindowTitle("Edit Filter")
                dlg.resize(400, 200)
                layout = QVBoxLayout()

                name_row = QHBoxLayout()
                name_label = QLabel("Filter Name:")
                name_edit = QLineEdit(f["name"])
                name_row.addWidget(name_label)
                name_row.addWidget(name_edit)
                layout.addLayout(name_row)

                regex_row = QHBoxLayout()
                regex_label = QLabel("Regex:")
                regex_edit = QLineEdit(f["filter"])
                regex_row.addWidget(regex_label)
                regex_row.addWidget(regex_edit)
                layout.addLayout(regex_row)

                action_row = QHBoxLayout()
                action_label = QLabel("Action:")
                action_combo = QComboBox()
                action_combo.addItems(["Delete", "Move", "Mark Unread", "Mark Read", "Mark as Important", "Mark as Unimportant"])
                if "action" in f:
                    action_combo.setCurrentText(f["action"])
                action_row.addWidget(action_label)
                action_row.addWidget(action_combo)
                layout.addLayout(action_row)

                btn_row = QHBoxLayout()
                save_btn = QPushButton("Save")
                cancel_btn = QPushButton("Cancel")
                btn_row.addWidget(save_btn)
                btn_row.addWidget(cancel_btn)
                layout.addLayout(btn_row)

                dlg.setLayout(layout)

                def save_clicked():
                    new_name = name_edit.text().strip()
                    new_regex = regex_edit.text().strip()
                    new_action = action_combo.currentText()
                    if not new_name:
                        QMessageBox.warning(dlg, "Edit Filter", "Filter name cannot be empty.")
                        return
                    if not new_regex:
                        QMessageBox.warning(dlg, "Edit Filter", "Regex cannot be empty.")
                        return
                    # Prevent duplicate names (except for this filter)
                    for j, other in enumerate(self.filters):
                        if j != idx and other["name"] == new_name:
                            QMessageBox.warning(dlg, "Edit Filter", f"A filter with the name '{new_name}' already exists.")
                            return
                    self.filters[idx]["name"] = new_name
                    self.filters[idx]["filter"] = new_regex
                    self.filters[idx]["action"] = new_action
                    self.save_filters()
                    self.refresh_filter_list()
                    self.update_original_filter_items()
                    QMessageBox.information(dlg, "Edit Filter", "Filter updated.")
                    self.editing_index = None
                    dlg.accept()

                save_btn.clicked.connect(save_clicked)
                cancel_btn.clicked.connect(dlg.reject)
                dlg.exec()
                return
        QMessageBox.warning(self, "Edit Filter", "Could not find the selected filter to edit.")
    def execute_selected_job(self):
        print("[DEEPDEBUG] execute_selected_job called")
        selected_items = self.job_list.selectedItems()
        print(f"[DEEPDEBUG] Selected items: {selected_items}")
        if not selected_items:
            print("[DEEPDEBUG] No job selected")
            QMessageBox.warning(self, "Execute Action", "Please select a job to execute.")
            return
        item = selected_items[0]
        name = item.text().split(":")[0]
        print(f"[DEEPDEBUG] Selected job name: {name}")
        jobs = self.load_jobs()
        print(f"[DEEPDEBUG] Loaded jobs: {jobs}")
        job = next((j for j in jobs if j["name"] == name), None)
        print(f"[DEEPDEBUG] Matched job: {job}")
        if not job:
            print("[DEEPDEBUG] Job not found")
            QMessageBox.warning(self, "Execute Action", "Job not found.")
            return
        parent = self.parent()
        print(f"[DEEPDEBUG] Parent: {parent}")
        if job["action"] == "Delete" and hasattr(parent, "emails_data") and hasattr(parent, "email_matches_regex"):
            regex = job.get("filter", "")
            print(f"[DEEPDEBUG] Job action is Delete, regex: {regex}")
            emails_data = getattr(parent, "emails_data", None)
            print(f"[DEEPDEBUG] Parent emails_data: {emails_data}")
            emails_to_delete = [email for email in emails_data if parent.email_matches_regex(email, regex)] if emails_data else []
            print(f"[DEEPDEBUG] Emails to delete: {emails_to_delete}")
            if emails_to_delete:
                uid_list = [e.get('uid') for e in emails_to_delete if e.get('uid')]
                print(f"[DEEPDEBUG] UID list to delete: {uid_list}")
                # Use EmailManager's batch permanent delete
                try:
                    from email_manager import EmailManager
                    manager = EmailManager()
                    print("[DEEPDEBUG] Batch permanent delete called via EmailManager.")
                    manager.delete_emails_by_uid_list(uid_list, permanent=True)
                    # Optionally, update UI or remove emails from view
                    if hasattr(parent, "remove_emails_by_uid_list"):
                        parent.remove_emails_by_uid_list(uid_list)
                except Exception as e:
                    print(f"[ERROR] Permanent delete failed: {e}")
                    QMessageBox.critical(self, "Permanent Delete Error", f"Failed to permanently delete emails: {e}")
                    return
            else:
                print("[DEEPDEBUG] No emails matched for deletion")
            QMessageBox.information(self, "Execute Action", f"Job '{name}' executed and matching emails permanently deleted.")
        else:
            print(f"[DEEPDEBUG] Job action is not Delete or parent missing required attributes. Action: {job['action']}")
            if hasattr(parent, "apply_filter_to_emails"):
                print(f"[DEEPDEBUG] Applying filter visually: {job['filter']}")
                parent.apply_filter_to_emails(job["filter"])
            QMessageBox.information(self, "Execute Action", f"Job '{name}' executed (action: {job['action']}).")

    def delete_selected_job(self):
        selected_items = self.job_list.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "Delete Action", "Please select a job to delete.")
            return
        item = selected_items[0]
        name = item.text().split(":")[0]
        jobs = self.load_jobs()
        job = next((j for j in jobs if j["name"] == name), None)
        jobs = [j for j in jobs if j["name"] != name]
        self.save_jobs(jobs)
        self.refresh_job_list()
        # If parent is EmailViewer, delete all emails matching this job's filter
        if job and hasattr(self.parent(), "emails_data") and hasattr(self.parent(), "delete_emails_by_uid_list") and hasattr(self.parent(), "email_matches_regex"):
            regex = job.get("filter", "")
            emails_to_delete = [email for email in self.parent().emails_data if self.parent().email_matches_regex(email, regex)]
            if emails_to_delete:
                uid_list = [e.get('uid') for e in emails_to_delete if e.get('uid')]
                self.parent().delete_emails_by_uid_list(uid_list)
        QMessageBox.information(self, "Delete Action", f"Job '{name}' deleted and matching emails removed.")

    def save_action_to_job(self):
        # Save the current filter/action as a job (persistent)
        name = self.name_edit.text().strip()
        if not name:
            QMessageBox.warning(self, "Save Action", "Please enter a filter name to save as a job.")
            return
        action = self.action_combo.currentText()
        # Try to extract the regex from the selected filter list entry
        regex = ""
        selected_items = self.filter_list.selectedItems()
        if selected_items:
            item_text = selected_items[0].text()
            if ":" in item_text:
                regex = item_text.rsplit(":", 1)[1].strip()
        if not regex:
            QMessageBox.warning(self, "Save Action", "Please select a filter with a non-empty regex before saving a job.")
            return
        # Load existing jobs
        jobs = self.load_jobs()
        # Prevent duplicate job names
        for job in jobs:
            if job["name"] == name:
                QMessageBox.warning(self, "Save Action", f"A job with the name '{name}' already exists.")
                return
        # If action is Move, get folder list if not cached, then prompt user
        folder = None
        if action == "Move":
            if not hasattr(self, '_move_folders_cache') or not self._move_folders_cache:
                # Fetch folders from Gmail
                try:
                    client = GmailClient()
                    client.load_credentials()
                    client.connect_imap()
                    status, folders = client.imap.list()
                    if status == 'OK' and folders:
                        # Parse folder names from IMAP response
                        folder_names = []
                        for f in folders:
                            # f is bytes, decode and parse
                            parts = f.decode().split(' "/" ')
                            if len(parts) == 2:
                                folder_names.append(parts[1].strip('"'))
                        self._move_folders_cache = folder_names
                    else:
                        QMessageBox.warning(self, "Move Action", "Could not retrieve folder list from server.")
                        return
                except Exception as e:
                    QMessageBox.critical(self, "Move Action", f"Failed to fetch folders: {e}")
                    return
            # Show folder picker dialog
            folder, ok = self.pick_folder_dialog(self._move_folders_cache)
            if not ok or not folder:
                # User cancelled
                return
        # Save job with folder if needed
        job = {"name": name, "filter": regex, "action": action}
        if folder:
            job["folder"] = folder
        jobs.append(job)
        self.save_jobs(jobs)
        self.refresh_job_list()
        QMessageBox.information(self, "Save Action", f"Job '{name}: {action}{' to ' + folder if folder else ''}' saved.")

    def pick_folder_dialog(self, folders):
        # Show a modal dialog with a list of folders, OK/Cancel
        from PySide6.QtWidgets import QDialog, QVBoxLayout, QListWidget, QPushButton, QHBoxLayout, QLabel
        dlg = QDialog(self)
        dlg.setWindowTitle("Select Folder")
        dlg.resize(350, 350)
        layout = QVBoxLayout()
        layout.addWidget(QLabel("Select a folder to move emails into:"))
        list_widget = QListWidget()
        for folder in folders:
            list_widget.addItem(folder)
        layout.addWidget(list_widget)
        btn_row = QHBoxLayout()
        ok_btn = QPushButton("OK")
        cancel_btn = QPushButton("Cancel")
        btn_row.addWidget(ok_btn)
        btn_row.addWidget(cancel_btn)
        layout.addLayout(btn_row)
        dlg.setLayout(layout)
        result = {"ok": False, "folder": None}
        def accept():
            sel = list_widget.currentItem()
            if sel:
                result["ok"] = True
                result["folder"] = sel.text()
                dlg.accept()
        def reject():
            dlg.reject()
        ok_btn.clicked.connect(accept)
        cancel_btn.clicked.connect(reject)
        if dlg.exec() == QDialog.Accepted and result["ok"]:
            return result["folder"], True
        return None, False

    def refresh_job_list(self):
        self.job_list.clear()
        jobs = self.load_jobs()
        for job in jobs:
            self.job_list.addItem(f"{job['name']}: {job['action']}")

    def load_jobs(self):
        jobs_file = "jobs.json"
        jobs = []
        if os.path.exists(jobs_file):
            with open(jobs_file, "r", encoding="utf-8") as f:
                jobs = json.load(f)
        # Deep debug: print first email loaded if available
        parent = self.parent()
        emails_data = getattr(parent, "emails_data", None)
        if emails_data and len(emails_data) > 0:
            print("[DEEPDEBUG] First email loaded (full dict):")
            print(json.dumps(emails_data[0], indent=2))
            print(f"[DEEPDEBUG] Keys: {list(emails_data[0].keys())}")
            for k, v in emails_data[0].items():
                print(f"    {k}: {v}")
        return jobs
    def save_jobs(self, jobs):
        jobs_file = "jobs.json"
        with open(jobs_file, "w", encoding="utf-8") as f:
            json.dump(jobs, f, indent=2)
    def clear_filter(self):
        self.name_edit.clear()
        self.rule_label.setText("Selected Filter: None")
        self.action_combo.setCurrentIndex(0)
        # Restore the original filter list
        if self._original_filter_items is not None:
            self.filter_list.clear()
            for text in self._original_filter_items:
                self.filter_list.addItem(QListWidgetItem(text))
        # Restore the full email list in the parent viewer
        if hasattr(self.parent(), "restore_emails"):
            self.parent().restore_emails()
        self.save_btn.clicked.connect(self.save_filter)
        self.delete_btn.clicked.connect(self.delete_filter)
        self.filter_list.model().rowsMoved.connect(self.save_filter_order)

    def showEvent(self, event):
        # Regenerate the filter when the dialog is shown, in case selected_emails changed
        self.generate_domain_regex_filter()
        super().showEvent(event)

    def generate_domain_regex_filter(self):
        # This function is now a no-op since the filter_edit is removed
        pass

    def load_filter_for_edit(self, item):
        # If multiple items are selected, only load the first one for editing
        selected_items = self.filter_list.selectedItems()
        if not selected_items:
            return
        item = selected_items[0]
        name = item.text().split(":")[0]
        for idx, f in enumerate(self.filters):
            if f["name"] == name:
                self.name_edit.setText(f["name"])
                self.regex_edit.setText(f["filter"])
                self.editing_index = idx
                self.rule_label.setText(f"Selected Filter: {name}")
                if "action" in f:
                    self.action_combo.setCurrentText(f["action"])
                else:
                    self.action_combo.setCurrentIndex(0)
                break

    def test_filter(self):
        # Apply the filter for the first selected item, using the regex from the list entry
        selected_items = self.filter_list.selectedItems()
        if not selected_items:
            return
        item = selected_items[0]
        item_text = item.text()
        if ":" in item_text:
            regex = item_text.rsplit(":", 1)[1].strip()
        else:
            regex = ""
        self.filter_applied.emit(regex)

    def save_filter(self):
        name = self.name_edit.text().strip()
        if not name:
            QMessageBox.warning(self, "Save Filter", "Please enter a filter name.")
            return
        action = self.action_combo.currentText()
        # Try to extract the regex from the selected filter list entry
        regex = ""
        selected_items = self.filter_list.selectedItems()
        if selected_items:
            item_text = selected_items[0].text()
            if ":" in item_text:
                regex = item_text.rsplit(":", 1)[1].strip()
        # If regex is still empty, use the value from the regex_edit field
        if not regex:
            regex = self.regex_edit.text().strip()
        if not regex:
            QMessageBox.warning(self, "Save Filter", "Please enter a regex for the filter.")
            return
        if self.editing_index is not None:
            self.filters[self.editing_index]["name"] = name
            self.filters[self.editing_index]["action"] = action
            self.filters[self.editing_index]["filter"] = regex
            self.save_filters()
            self.refresh_filter_list()
            self.update_original_filter_items()
            # Remove <New Filter> placeholder if present
            for i in reversed(range(self.filter_list.count())):
                item = self.filter_list.item(i)
                if item.text().startswith("<New Filter>:"):
                    self.filter_list.takeItem(i)
            # Select the updated filter in the list
            for i in range(self.filter_list.count()):
                item = self.filter_list.item(i)
                if item.text().startswith(f"{name}:"):
                    self.filter_list.setCurrentItem(item)
                    break
            QMessageBox.information(self, "Save Filter", "Filter updated.")
            self.editing_index = None
        else:
            # Check for duplicate in file, not just in-memory list
            file_filters = self.load_filters()
            for f in file_filters:
                if f["name"] == name:
                    QMessageBox.warning(self, "Save Filter", "A filter with this name already exists in the file. Select it to edit.")
                    return
            self.filters.append({"name": name, "filter": regex, "action": action})
            self.save_filters()
            self.refresh_filter_list()
            self.update_original_filter_items()
            # Remove <New Filter> placeholder if present
            for i in reversed(range(self.filter_list.count())):
                item = self.filter_list.item(i)
                if item.text().startswith("<New Filter>:"):
                    self.filter_list.takeItem(i)
            # Select the newly added filter in the list
            for i in range(self.filter_list.count()):
                item = self.filter_list.item(i)
                if item.text().startswith(f"{name}:"):
                    self.filter_list.setCurrentItem(item)
                    break
            QMessageBox.information(self, "Save Filter", "New filter created.")
        if hasattr(self.parent(), "email_table"):
            self.parent().email_table.clearSelection()

    def delete_filter(self):
        selected_items = self.filter_list.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "Delete Filter", "Please select at least one filter to delete.")
            return
        names = [item.text().split(":")[0] for item in selected_items]
        # Remove from in-memory list
        self.filters = [f for f in self.filters if f["name"] not in names]
        # Save to JSON
        self.save_filters()
        # Reload from JSON to ensure sync
        self.filters = self.load_filters()
        # Refresh UI
        self.refresh_filter_list()
        self.update_original_filter_items()
        self.name_edit.clear()
        QMessageBox.information(self, "Delete Filter", f"Deleted filter(s): {', '.join(names)}.")

    def refresh_filter_list(self):
        self.filter_list.clear()
        for f in self.filters:
            # Show each filter on its own line, just the name and full filter for clarity
            item = QListWidgetItem(f"{f['name']}: {f['filter']}")
            self.filter_list.addItem(item)
        self.update_original_filter_items()

    def save_filter_order(self):
        new_order = []
        for i in range(self.filter_list.count()):
            text = self.filter_list.item(i).text()
            name = text.split(":")[0]
            for f in self.filters:
                if f["name"] == name:
                    new_order.append(f)
                    break
        self.filters = new_order
        self.save_filters()

    def load_filters(self):
        # Use parent's method for consistency
        if hasattr(self.parent(), 'load_filters'):
            return self.parent().load_filters()
        return []

    def save_filters(self):
        # Use parent's method for consistency
        if hasattr(self.parent(), 'save_filters'):
            self.parent().save_filters(self.filters)
        else:
            try:
                abs_path = os.path.abspath(FILTERS_FILE)
                print(f"[DEBUG] Saving filters to: {abs_path}")
                print(f"[DEBUG] Filters data: {json.dumps(self.filters, indent=2)}")
                with open(FILTERS_FILE, "w", encoding="utf-8") as f:
                    json.dump(self.filters, f, indent=2)
                print("[DEBUG] Save successful.")
            except Exception as e:
                print(f"[ERROR] Failed to save filters: {e}")
                QMessageBox.critical(self, "Save Error", f"Failed to save filters: {e}")

class DateTableWidgetItem(QTableWidgetItem):
    def __init__(self, date_str):
        # Ensure date_str is always a string
        super().__init__(str(date_str))

class ManageRulesDialog(QDialog):
    def __init__(self, parent):
        super().__init__(parent)
        self.setWindowTitle("Manage Rules")
        self.resize(700, 400)
        self.rules = parent.load_rules()
        self.parent = parent
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()
        self.rule_list = QListWidget()
        self.rule_list.setDragDropMode(QListWidget.InternalMove)
        self.rule_list.setSelectionMode(QListWidget.SingleSelection)
        self.rule_list.setStyleSheet("QListWidget::item { font-family: monospace; font-size: 13px; min-height: 28px; } QListWidget::item:selected { background: #0078d7; color: white; }")
        self.refresh_rule_list()
        layout.addWidget(QLabel("Saved Rules (drag to reorder, single-click to edit):"))
        layout.addWidget(self.rule_list)

        btn_layout = QHBoxLayout()
        self.edit_btn = QPushButton("Edit Rule")
        self.delete_btn = QPushButton("Delete Rule")
        self.execute_btn = QPushButton("Execute Rule")
        btn_layout.addWidget(self.edit_btn)
        btn_layout.addWidget(self.delete_btn)
        btn_layout.addWidget(self.execute_btn)
        layout.addLayout(btn_layout)

        self.setLayout(layout)

        self.edit_btn.clicked.connect(self.edit_rule)
        self.delete_btn.clicked.connect(self.delete_rule)
        self.execute_btn.clicked.connect(self.execute_rule)
        self.rule_list.model().rowsMoved.connect(self.save_rule_order)

    def refresh_rule_list(self):
        self.rule_list.clear()
        for r in self.rules:
            item = QListWidgetItem(f"{r['name']}: {r['filter'][:40]}... [{r['action']}]")
            self.rule_list.addItem(item)

    def edit_rule(self):
        # Implement rule editing logic here
        pass

    def delete_rule(self):
        selected_items = self.rule_list.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "Delete Rule", "Please select a rule to delete.")
            return
        item = selected_items[0]
        name = item.text().split(":")[0]
        self.rules = [r for r in self.rules if r["name"] != name]
        self.parent.save_rules(self.rules)
        self.refresh_rule_list()
        QMessageBox.information(self, "Delete Rule", f"Rule '{name}' deleted.")

    def execute_rule(self):
        selected_items = self.rule_list.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "Execute Rule", "Please select a rule to execute.")
            return
        item = selected_items[0]
        name = item.text().split(":")[0]
        rule = next((r for r in self.rules if r["name"] == name), None)
        if not rule:
            QMessageBox.warning(self, "Execute Rule", "Rule not found.")
            return
        # Apply filter and action (demo: just filter emails)
        self.parent.apply_filter_to_emails(rule["filter"])
        QMessageBox.information(self, "Execute Rule", f"Rule '{name}' executed (action: {rule['action']}).")

    def save_rule_order(self):
        new_order = []
        for i in range(self.rule_list.count()):
            text = self.rule_list.item(i).text()
            name = text.split(":")[0]
            for r in self.rules:
                if r["name"] == name:
                    new_order.append(r)
                    break
        self.rules = new_order
        self.parent.save_rules(self.rules)

class EmailViewer(QWidget):
    def load_filters(self):
        if os.path.exists(FILTERS_FILE):
            with open(FILTERS_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        return []

    def save_filters(self, filters):
        try:
            abs_path = os.path.abspath(FILTERS_FILE)
            print(f"[DEBUG] Saving filters to: {abs_path}")
            print(f"[DEBUG] Filters data: {json.dumps(filters, indent=2)}")
            with open(FILTERS_FILE, "w", encoding="utf-8") as f:
                json.dump(filters, f, indent=2)
            print("[DEBUG] Save successful.")
        except Exception as e:
            print(f"[ERROR] Failed to save filters: {e}")
            QMessageBox.critical(self, "Save Error", f"Failed to save filters: {e}")
    def apply_filter_to_emails(self, regex):
        """
        Filter emails_data by regex (on 'from', 'subject', or 'date') and update the table.
        """
        import re
        if not regex:
            # Restore full list
            filtered = self._emails_data_buffer if self._emails_data_buffer is not None else self.emails_data
        else:
            pattern = re.compile(regex, re.IGNORECASE)
            filtered = [e for e in (self._emails_data_buffer if self._emails_data_buffer is not None else self.emails_data)
                        if pattern.search(str(e.get('from', ''))) or pattern.search(str(e.get('subject', ''))) or pattern.search(str(e.get('date', '')))]
        self.emails_data = filtered
        self.email_table.setRowCount(len(filtered))
        for row_position, email in enumerate(filtered):
            self.set_email_row(row_position, email)
        self.status_label.setText(f"Filtered: {len(filtered)} emails match '{regex}'" if regex else f"Showing all emails.")
    def read_selected_emails(self):
        selected = self.get_selected_emails()
        if not selected:
            self.status_label.setText("No emails selected to read.")
            return
        errors = []
        for email_info in selected:
            uid = email_info.get('uid')
            if not uid:
                errors.append("Could not find UID for an email.")
                continue
            try:
                client = GmailClient()
                client.load_credentials()
                client.connect_imap()
                if hasattr(client, 'imap') and client.imap:
                    client.imap.select('INBOX')
                msg = client._fetch_email(uid.encode())
                html_body = self.extract_html_body(msg)
                import tempfile, webbrowser
                with tempfile.NamedTemporaryFile(delete=False, suffix=".html", mode="w", encoding="utf-8") as f:
                    f.write(html_body)
                    temp_path = f.name
                webbrowser.open(temp_path)
            except Exception as e:
                errors.append(f"Error displaying email UID {uid}: {e}")
            finally:
                if 'client' in locals() and client:
                    client.logout()
        if errors:
            self.status_label.setText("; ".join(errors))
        else:
            self.status_label.setText(f"Read {len(selected)} emails.")

    def delete_selected_emails(self, permanent=False):
        selected = self.get_selected_emails()
        if not selected:
            self.status_label.setText("No emails selected to delete.")
            return
        try:
            print("[DEEPDEBUG] Selected emails for deletion:")
            for idx, e in enumerate(selected):
                print(f"  Email {idx}: {e}")
                uid = e.get('uid')
                print(f"    UID type: {type(uid)}, value: {uid}")
            uid_list = [e.get('uid') for e in selected if e.get('uid')]
            print(f"[DEEPDEBUG] UID list to delete: {uid_list}")
            self.manager.delete_emails_by_uid_list(uid_list, permanent=permanent)
            self.status_label.setText(f"Deleted {len(uid_list)} emails{' permanently' if permanent else ''}.")
        except Exception as e:
            self.status_label.setText(f"Error deleting emails: {e}")

    def forward_selected_emails(self):
        selected = self.get_selected_emails()
        if not selected:
            self.status_label.setText("No emails selected to forward.")
            return
        self.status_label.setText(f"Forwarded {len(selected)} emails.")

    def move_selected_emails(self):
        selected = self.get_selected_emails()
        if not selected:
            self.status_label.setText("No emails selected to move.")
            return
        # Connect to IMAP and get folder list
        try:
            client = GmailClient()
            client.load_credentials()
            client.connect_imap()
            status, folders = client.imap.list()
            if status != 'OK' or not folders:
                self.status_label.setText("Could not retrieve folder list from server.")
                return
            # Parse folder names from IMAP response
            folder_names = []
            for f in folders:
                parts = f.decode().split(' "/" ')
                if len(parts) == 2:
                    folder_names.append(parts[1].strip('"'))
            if not folder_names:
                self.status_label.setText("No folders found on server.")
                return
        except Exception as e:
            self.status_label.setText(f"Failed to fetch folders: {e}")
            return
        # Prompt user to pick a folder
        from PySide6.QtWidgets import QDialog, QVBoxLayout, QListWidget, QPushButton, QHBoxLayout, QLabel
        dlg = QDialog(self)
        dlg.setWindowTitle("Select Folder to Move Emails Into")
        dlg.resize(350, 350)
        layout = QVBoxLayout()
        layout.addWidget(QLabel("Select a folder to move emails into:"))
        list_widget = QListWidget()
        for folder in folder_names:
            list_widget.addItem(folder)
        layout.addWidget(list_widget)
        btn_row = QHBoxLayout()
        move_btn = QPushButton("Move")
        cancel_btn = QPushButton("Cancel")
        btn_row.addWidget(move_btn)
        btn_row.addWidget(cancel_btn)
        layout.addLayout(btn_row)
        dlg.setLayout(layout)
        result = {"ok": False, "folder": None}
        def accept():
            sel = list_widget.currentItem()
            if sel:
                result["ok"] = True
                result["folder"] = sel.text()
                dlg.accept()
        def reject():
            dlg.reject()
        move_btn.clicked.connect(accept)
        cancel_btn.clicked.connect(reject)
        if dlg.exec() != QDialog.Accepted or not result["ok"] or not result["folder"]:
            self.status_label.setText("Move cancelled.")
            return
        folder = result["folder"]
        # Move emails to selected folder
        errors = []
        for email_info in selected:
            uid = email_info.get('uid')
            if not uid:
                errors.append("Could not find UID for an email.")
                continue
            try:
                # Copy to folder
                copy_result, copy_data = client.imap.uid('COPY', uid, folder)
                if copy_result != 'OK':
                    errors.append(f"Failed to copy UID {uid} to {folder}: {copy_data}")
                    continue
                # Mark as deleted in INBOX
                store_result, store_data = client.imap.uid('STORE', uid, '+FLAGS', r'(\Deleted)')
                if store_result != 'OK':
                    errors.append(f"Failed to mark UID {uid} as deleted: {store_data}")
            except Exception as e:
                errors.append(f"Error moving UID {uid}: {e}")
        # Expunge INBOX to remove deleted
        try:
            client.imap.expunge()
        except Exception as e:
            errors.append(f"Error expunging INBOX: {e}")
        finally:
            client.logout()
        if errors:
            self.status_label.setText("; ".join(errors))
        else:
            self.status_label.setText(f"Moved {len(selected)} emails to {folder}.")

    def mark_read_selected_emails(self):
        selected = self.get_selected_emails()
        if not selected:
            self.status_label.setText("No emails selected to mark as read.")
            return
        self.status_label.setText(f"Marked {len(selected)} emails as read.")

    def mark_unread_selected_emails(self):
        selected = self.get_selected_emails()
        if not selected:
            self.status_label.setText("No emails selected to mark as unread.")
            return
        self.status_label.setText(f"Marked {len(selected)} emails as unread.")

    def mark_important_selected_emails(self):
        selected = self.get_selected_emails()
        if not selected:
            self.status_label.setText("No emails selected to mark as important.")
            return
        self.status_label.setText(f"Marked {len(selected)} emails as important.")

    def mark_unimportant_selected_emails(self):
        selected = self.get_selected_emails()
        if not selected:
            self.status_label.setText("No emails selected to mark as unimportant.")
            return
        self.status_label.setText(f"Marked {len(selected)} emails as unimportant.")
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Gmail Email Viewer")
        self.resize(1260, 770)
        layout = QVBoxLayout()

        # Top bar with status and main buttons
        self.status_label = QLabel("Click 'Load Emails' to fetch emails.")
        layout.addWidget(self.status_label)

        top_btn_bar = QHBoxLayout()
        self.load_emails_btn = QPushButton("Load Emails")
        self.create_filters_btn = QPushButton("Create Filters")
        self.manage_filters_btn = QPushButton("Manage Filters")
        top_btn_bar.addWidget(self.load_emails_btn)
        top_btn_bar.addWidget(self.create_filters_btn)
        top_btn_bar.addWidget(self.manage_filters_btn)

        # Add vertical bar (QFrame) after Manage Filters button
        from PySide6.QtWidgets import QFrame
        vline = QFrame()
        vline.setFrameShape(QFrame.VLine)
        vline.setFrameShadow(QFrame.Sunken)
        top_btn_bar.addWidget(vline)

        # Add action buttons after the vertical bar
        self.read_btn = QPushButton("Read")
        self.forward_btn = QPushButton("Forward")
        self.move_btn = QPushButton("Move")
        self.delete_btn = QPushButton("Delete")
        self.perm_delete_btn = QPushButton("Permanent Delete")
        self.mark_read_btn = QPushButton("Mark as Read")
        self.mark_unread_btn = QPushButton("Mark as Unread")
        self.mark_important_btn = QPushButton("Mark as Important")
        self.mark_unimportant_btn = QPushButton("Mark as Unimportant")
        for btn in [self.read_btn, self.forward_btn, self.move_btn, self.delete_btn, self.perm_delete_btn, self.mark_read_btn, self.mark_unread_btn, self.mark_important_btn, self.mark_unimportant_btn]:
            top_btn_bar.addWidget(btn)

        top_btn_bar.addStretch()
        layout.addLayout(top_btn_bar)

        # Main email table
        self.email_table = QTableWidget()
        self.email_table.setColumnCount(3)
        self.email_table.setHorizontalHeaderLabels(["From", "Date/Time", "Subject"])
        self.email_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.email_table.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.email_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.email_table.setSortingEnabled(True)
        self.email_table.verticalHeader().setVisible(False)
        layout.addWidget(self.email_table)

        # Set column resize modes: first and second columns are interactive (user-resizable), third column stretches
        header = self.email_table.horizontalHeader()
        from PySide6.QtWidgets import QHeaderView
        header.setSectionResizeMode(0, QHeaderView.Interactive)
        header.setSectionResizeMode(1, QHeaderView.Interactive)
        header.setSectionResizeMode(2, QHeaderView.Stretch)

        # Set initial column widths to match the screenshot
        self.email_table.setColumnWidth(0, 260)  # From
        self.email_table.setColumnWidth(1, 170)  # Date/Time

        # Bottom rule bar
        bottom_bar = QHBoxLayout()
        self.rule_display = QLabel("Current Rule: None")
        bottom_bar.addWidget(self.rule_display)
        bottom_bar.addStretch()
        self.save_rule_btn = QPushButton("Save Rule")
        self.save_rule_btn.setFixedWidth(120)
        self.manage_rules_btn = QPushButton("Manage Rules")
        self.manage_rules_btn.setFixedWidth(120)
        bottom_bar.addWidget(self.save_rule_btn)
        bottom_bar.addWidget(self.manage_rules_btn)
        layout.addLayout(bottom_bar)

        self.setLayout(layout)

        # Button connections
        self.load_emails_btn.clicked.connect(self.load_emails)
        self.create_filters_btn.clicked.connect(self.open_create_filters)
        self.manage_filters_btn.clicked.connect(self.open_manage_filters)
        self.save_rule_btn.clicked.connect(self.save_rule)
        self.manage_rules_btn.clicked.connect(self.open_manage_rules)

        # Action button connections
        self.read_btn.clicked.connect(self.read_selected_emails)
        self.delete_btn.clicked.connect(self.delete_selected_emails)
        self.perm_delete_btn.clicked.connect(lambda: self.delete_selected_emails(permanent=True))
        self.move_btn.clicked.connect(self.move_selected_emails)

        # Double-click on email row opens in browser
        self.email_table.doubleClicked.connect(self.show_email_in_browser)

        self.client = None
        self.emails_data = []
        self._emails_data_buffer = None
        self.manager = EmailManager()

    def open_create_filters(self):
        selected_emails = self.get_selected_emails()
        dlg = FilterDialog(self, selected_emails)
        dlg.filter_applied.connect(self.apply_filter_to_emails)
        dlg.exec()

    def open_manage_filters(self):
        # Open FilterDialog with no selected emails (manage mode)
        dlg = FilterDialog(self, [])
        dlg.filter_applied.connect(self.apply_filter_to_emails)
        dlg.exec()

    def set_email_row(self, row_position, email):
        # Deep debug: print the full email dict and row index
        print(f"[DEEPDEBUG] set_email_row({row_position}): {email}")
        from_value = email.get('from', '')
        if not from_value:
            print(f"[DEEPDEBUG] WARNING: Missing 'from' for row {row_position}, email: {email}")
        from_item = QTableWidgetItem(str(from_value))
        # Truncate timestamp after minutes
        date_str = email.get('date', '')
        match = re.search(r'^(.{16})', date_str)
        if match:
            date_str = match.group(1)
        date_item = DateTableWidgetItem(date_str)
        subject_value = email.get('subject', '')
        if not subject_value:
            print(f"[DEEPDEBUG] WARNING: Missing 'subject' for row {row_position}, email: {email}")
        subject_item = QTableWidgetItem(str(subject_value))
        from_item.setData(Qt.UserRole, email.get('uid'))
        self.email_table.setItem(row_position, 0, from_item)
        self.email_table.setItem(row_position, 1, date_item)
        self.email_table.setItem(row_position, 2, subject_item)
        # Print what is actually set in the table
        for col in range(self.email_table.columnCount()):
            item = self.email_table.item(row_position, col)
            print(f"[DEEPDEBUG] After set: Row {row_position} Col {col} Value: {item.text()} (should be: {email.get('from', '')})")

    @staticmethod
    def extract_html_body(msg):
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == "text/html":
                    return part.get_payload(decode=True).decode(errors="ignore")
        else:
            if msg.get_content_type() == "text/html":
                return msg.get_payload(decode=True).decode(errors="ignore")
        payload = msg.get_payload(decode=True)
        return "<pre>" + (payload.decode(errors="ignore") if payload else "No HTML content.") + "</pre>"

    def load_emails(self):
        self.status_label.setText("Loading...")
        QApplication.processEvents()
        try:
            self.client = GmailClient()
            self.client.load_credentials()
            self.client.connect_imap()
            # Use cache for speed, only fetch new headers
            emails = self.client.list_emails(limit=1000, use_cache=True)
            print("[DEEPDEBUG] Email keys and values for first 5 emails loaded:")
            for idx, email in enumerate(emails[:5]):
                print(f"  Email {idx} keys: {list(email.keys())}")
                for k, v in email.items():
                    print(f"    {k}: {v}")
            self.email_table.setUpdatesEnabled(False)
            self.email_table.setRowCount(len(emails))
            self.emails_data = emails
            self._emails_data_buffer = list(emails)  # Save a cache of the full list
            for row_position, email in enumerate(emails):
                self.set_email_row(row_position, email)
            self.email_table.setUpdatesEnabled(True)
            self.email_table.sortItems(1, Qt.DescendingOrder)
            self.status_label.setText(f"Loaded {len(emails)} emails.")
        except Exception as e:
            import traceback
            self.status_label.setText(f"Error: {e}")
            print(traceback.format_exc())
        finally:
            if self.client:
                self.client.logout()

    def get_selected_emails(self):
        selected_rows = set(idx.row() for idx in self.email_table.selectedIndexes())
        selected_emails = []
        for row in selected_rows:
            uid = self.email_table.item(row, 0).data(Qt.UserRole)
            email_info = next((e for e in self.emails_data if e.get('uid') == uid), None)
            if email_info:
                selected_emails.append(email_info)
        return selected_emails

    def save_filter(self):
        name = self.name_edit.text().strip()
        if not name:
            QMessageBox.warning(self, "Save Filter", "Please enter a filter name.")
            return
        action = self.action_combo.currentText()
        # Try to extract the regex from the selected filter list entry
        regex = ""
        selected_items = self.filter_list.selectedItems()
        if selected_items:
            item_text = selected_items[0].text()
            if ":" in item_text:
                regex = item_text.rsplit(":", 1)[1].strip()
        if self.editing_index is not None:
            self.filters[self.editing_index]["name"] = name
            self.filters[self.editing_index]["action"] = action
            self.filters[self.editing_index]["filter"] = regex
            self.save_filters()
            self.filters = self.load_filters()  # Reload from file to ensure sync
            self.refresh_filter_list()
            self.update_original_filter_items()
            QMessageBox.information(self, "Save Filter", "Filter updated.")
            self.editing_index = None
        else:
            # Add new filter
            for f in self.filters:
                if f["name"] == name:
                    QMessageBox.warning(self, "Save Filter", "A filter with this name already exists. Select it to edit.")
                    return
            self.filters.append({"name": name, "filter": regex, "action": action})
            self.save_filters()
            self.filters = self.load_filters()  # Reload from file to ensure sync
            self.refresh_filter_list()
            self.update_original_filter_items()
            QMessageBox.information(self, "Save Filter", "New filter created.")
        if hasattr(self.parent(), "email_table"):
            self.parent().email_table.clearSelection()

    def delete_filter(self):
        selected_items = self.filter_list.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "Delete Filter", "Please select at least one filter to delete.")
            return
        names = [item.text().split(":")[0] for item in selected_items]
        # Remove from in-memory list
        self.filters = [f for f in self.filters if f["name"] not in names]
        # Save to JSON
        self.save_filters()
        # Reload from JSON to ensure sync
        self.filters = self.load_filters()
        # Refresh UI
        self.refresh_filter_list()
        self.update_original_filter_items()
        self.name_edit.clear()
        QMessageBox.information(self, "Delete Filter", f"Deleted filter(s): {', '.join(names)}.")

    def save_rule(self):
        rule_name, ok = QInputDialog.getText(self, "Save Rule", "Enter rule name:")
        if not ok or not rule_name.strip():
            return
        filters = self.load_filters()
        if not filters:
            QMessageBox.warning(self, "Save Rule", "No filter to save as a rule.")
            return
        last_filter = filters[-1]
        rule = {
            "name": rule_name.strip(),
            "filter": last_filter["filter"],
            "action": last_filter.get("action", "Delete")
        }
        rules = self.load_rules()
        rules.append(rule)
        self.save_rules(rules)
        self.rule_display.setText(f"Current Rule: {rule['name']} ({rule['action']})")
        QMessageBox.information(self, "Save Rule", f"Rule '{rule['name']}' saved.")

    def load_rules(self):
        if os.path.exists(RULES_FILE):
            with open(RULES_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        return []

    def save_rules(self, rules):
        with open(RULES_FILE, "w", encoding="utf-8") as f:
            json.dump(rules, f, indent=2)

    def open_manage_rules(self):
        dlg = ManageRulesDialog(self)
        dlg.exec()

    def show_email_in_browser(self, index):
        row = index.row()
        if row < 0:
            return
        uid = self.email_table.item(row, 0).data(Qt.UserRole)
        if not uid:
            self.status_label.setText("Could not find UID for this email.")
            return
        email_info = next((e for e in self.emails_data if e.get('uid') == uid), None)
        if not email_info:
            self.status_label.setText("Could not find email data for this UID.")
            return
        try:
            self.client = GmailClient()
            self.client.load_credentials()
            self.client.connect_imap()
            if hasattr(self.client, 'imap') and self.client.imap:
                self.client.imap.select('INBOX')
            msg = self.client._fetch_email(uid.encode())
            html_body = self.extract_html_body(msg)
            import tempfile, webbrowser
            with tempfile.NamedTemporaryFile(delete=False, suffix=".html", mode="w", encoding="utf-8") as f:
                f.write(html_body)
                temp_path = f.name
            webbrowser.open(temp_path)
        except Exception as e:
            self.status_label.setText(f"Error displaying email: {e}")
        finally:
            if self.client:
                self.client.logout()

def main():
    app = QApplication(sys.argv)
    viewer = EmailViewer()
    viewer.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
