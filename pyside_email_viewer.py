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
        # Insert a new <New Filter> at the top
        new_item = QListWidgetItem(f"{new_label}")
        self.filter_list.insertItem(0, new_item)
        self.filter_list.setCurrentItem(new_item)
    filter_applied = Signal(str)  # regex string

    def __init__(self, parent, selected_emails):
        super().__init__(parent)
        self.setWindowTitle("Filters")
        self.resize(700, 300)
        self.selected_emails = selected_emails
        self.filters = self.load_filters()
        self._original_filter_items = None  # For restoring filter list
        self.editing_index = None  # Track which filter is being edited
        self.init_ui()
        # Only generate a filter if 2 or more are selected
        if self.selected_emails and len(self.selected_emails) > 1:
            # Analyze the emails and generate a filter
            domains = set()
            for email in self.selected_emails:
                sender = email.get('from', '')
                match = re.search(r'@([A-Za-z0-9.-]+\.[A-Za-z]{2,})', sender)
                if match:
                    domains.add(match.group(1))
            if domains:
                filter_name = f"Filter: {', '.join(domains)}"
                regex = '|'.join(domains)
            else:
                filter_name = "New Filter"
                regex = ''
            # Remove any existing <New Filter> or Filter: at the top
            for i in reversed(range(self.filter_list.count())):
                if self.filter_list.item(i).text().startswith("<New Filter>:") or self.filter_list.item(i).text().startswith("Filter: "):
                    self.filter_list.takeItem(i)
            # Insert the new filter at the top
            new_label = f"{filter_name}: {regex}"
            new_item = QListWidgetItem(new_label)
            self.filter_list.insertItem(0, new_item)
            self.filter_list.setCurrentItem(new_item)
            self.name_edit.setText(filter_name)
            self.editing_index = None
            self.rule_label.setText(f"Selected Filter: {filter_name}")
            # Do NOT call refresh_filter_list here, as it would overwrite the generated filter
        else:
            self.new_filter()

        # Now that the filter list is fully initialized, save the original items
        self.update_original_filter_items()

    def update_original_filter_items(self):
        self._original_filter_items = [self.filter_list.item(i).text() for i in range(self.filter_list.count())]

    def init_ui(self):
        layout = QVBoxLayout()
        layout.addWidget(QLabel("Select a Filter to Edit:"))
        new_btn = QPushButton("New Filter")
        new_btn.clicked.connect(self.new_filter)
        layout.addWidget(new_btn)
        self.filter_list = QListWidget()
        self.filter_list.setDragDropMode(QListWidget.InternalMove)
        self.filter_list.setSelectionMode(QListWidget.ExtendedSelection)
        self.filter_list.setStyleSheet("QListWidget::item { font-family: monospace; font-size: 13px; min-height: 28px; } QListWidget::item:selected { background: #0078d7; color: white; }")
        self.filter_list.itemClicked.connect(self.load_filter_for_edit)
        self.refresh_filter_list()
        layout.addWidget(self.filter_list)

        name_row = QHBoxLayout()
        name_label = QLabel("Filter Name:")
        self.name_edit = QLineEdit()
        self.name_edit.setPlaceholderText("Enter filter name")
        name_row.addWidget(name_label)
        name_row.addWidget(self.name_edit)
        layout.addLayout(name_row)

        btn_layout = QHBoxLayout()
        self.test_btn = QPushButton("Apply Filter")
        self.clear_btn = QPushButton("Clear Filter")
        self.save_btn = QPushButton("Save Filter")
        self.delete_btn = QPushButton("Delete Filter")
        btn_layout.addWidget(self.test_btn)
        btn_layout.addWidget(self.clear_btn)
        btn_layout.addWidget(self.save_btn)
        btn_layout.addWidget(self.delete_btn)
        layout.addLayout(btn_layout)

        # --- Rule Builder Section ---
        self.rule_label = QLabel("Selected Filter: None")
        layout.addWidget(self.rule_label)

        action_row = QHBoxLayout()
        action_label = QLabel("Select Action:")
        self.action_combo = QComboBox()
        self.action_combo.addItems(["Delete", "Move", "Mark Unread", "Mark Read"])
        action_row.addWidget(action_label)
        action_row.addWidget(self.action_combo)
        layout.addLayout(action_row)

        self.setLayout(layout)

        self.test_btn.clicked.connect(self.test_filter)
        self.clear_btn.clicked.connect(self.clear_filter)
    def clear_filter(self):
        self.name_edit.clear()
        self.rule_label.setText("Selected Filter: None")
        self.action_combo.setCurrentIndex(0)
        # Restore the original filter list
        if self._original_filter_items is not None:
            self.filter_list.clear()
            for text in self._original_filter_items:
                self.filter_list.addItem(QListWidgetItem(text))
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
        if self.editing_index is not None:
            self.filters[self.editing_index]["name"] = name
            self.filters[self.editing_index]["action"] = action
            self.filters[self.editing_index]["filter"] = regex
            self.save_filters()
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
        self.filters = [f for f in self.filters if f["name"] not in names]
        self.save_filters()
        self.refresh_filter_list()
        self.name_edit.clear()
        # Removed self.filter_edit.clear() as there is no filter_edit widget
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
        if os.path.exists(FILTERS_FILE):
            with open(FILTERS_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        return []

    def save_filters(self):
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
    def apply_filter_to_emails(self, regex):
        """
        Filter emails in the table by the given regex (applies to the 'From' field, extracted email address, display name, and subject).
        """
        print(f"[DEBUG] Filtering with regex: '{regex}'")
        if not regex:
            print("[DEBUG] No regex provided, showing all emails.")
            filtered_emails = self.emails_data
        else:
            try:
                pattern = re.compile(regex, re.IGNORECASE)
            except re.error:
                print(f"[ERROR] Invalid regex: {regex}")
                QMessageBox.warning(self, "Invalid Regex", f"The filter regex is invalid: {regex}")
                return
            filtered_emails = []
            for email in self.emails_data:
                from_field = str(email.get('from', ''))
                subject_field = str(email.get('subject', ''))
                # Extract email address from 'from' field
                email_match = re.search(r'<([^>]+)>', from_field)
                email_addr = email_match.group(1) if email_match else from_field
                # Extract display name (before <)
                display_name = from_field.split('<')[0].strip() if '<' in from_field else from_field
                from_match = pattern.search(from_field)
                email_addr_match = pattern.search(email_addr)
                display_name_match = pattern.search(display_name)
                subject_match = pattern.search(subject_field)
                print(f"[DEBUG] Email FROM: '{from_field}' | EMAIL: '{email_addr}' | DISPLAY: '{display_name}' | SUBJECT: '{subject_field}' | from_match: {from_match is not None} | email_addr_match: {email_addr_match is not None} | display_name_match: {display_name_match is not None} | subject_match: {subject_match is not None}")
                if from_match or email_addr_match or display_name_match or subject_match:
                    filtered_emails.append(email)
        print(f"[DEBUG] Filtered emails count: {len(filtered_emails)}")
        self.email_table.setUpdatesEnabled(False)
        self.email_table.setRowCount(len(filtered_emails))
        for row_position, email in enumerate(filtered_emails):
            self.set_email_row(row_position, email)
        self.email_table.setUpdatesEnabled(True)
        self.email_table.sortItems(1, Qt.DescendingOrder)
        self.status_label.setText(f"Filtered: {len(filtered_emails)} emails.")
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

        # Double-click on email row opens in browser
        self.email_table.doubleClicked.connect(self.show_email_in_browser)

        self.client = None
        self.emails_data = []
        self._emails_data_buffer = None

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
        # Always pass a string to QTableWidgetItem
        from_item = QTableWidgetItem(str(email.get('from', '')))
        # Truncate timestamp after minutes
        date_str = email.get('date', '')
        match = re.search(r'^(.{16})', date_str)
        if match:
            date_str = match.group(1)
        date_item = DateTableWidgetItem(date_str)
        subject_item = QTableWidgetItem(str(email.get('subject', '')))
        from_item.setData(Qt.UserRole, email.get('uid'))
        self.email_table.setItem(row_position, 0, from_item)
        self.email_table.setItem(row_position, 1, date_item)
        self.email_table.setItem(row_position, 2, subject_item)

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
        self.status_label.setText("Loading emails...")
        QApplication.processEvents()
        try:
            self.client = GmailClient()
            self.client.load_credentials()
            self.client.connect_imap()
            emails = self.client.list_emails(limit=100)  # Load up to 100 emails for speed
            self.email_table.setUpdatesEnabled(False)
            self.email_table.setRowCount(len(emails))
            self.emails_data = emails
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
        if hasattr(self, 'email_table'):
            self.email_table.sortItems(1, Qt.DescendingOrder)

    def delete_filter(self):
        selected_items = self.filter_list.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "Delete Filter", "Please select at least one filter to delete.")
            return
        names = [item.text().split(":")[0] for item in selected_items]
        self.filters = [f for f in self.filters if f["name"] not in names]
        self.save_filters()
        self.refresh_filter_list()
        self.update_original_filter_items()
        self.name_edit.clear()
        self.filter_edit.clear()
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