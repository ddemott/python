
import unittest
from unittest.mock import patch
from pyside_email_viewer import EmailViewer, FilterDialog, ManageRulesDialog, DateTableWidgetItem
from PySide6.QtWidgets import QApplication, QWidget
import sys

app = QApplication.instance() or QApplication(sys.argv)

class TestEmailViewer(unittest.TestCase):
    def setUp(self):
        self.viewer = EmailViewer()

    def test_set_email_row_valid(self):
        email = {'from': 'test@example.com', 'date': '2025-07-20 12:34', 'subject': 'Hello', 'uid': '123'}
        self.viewer.email_table.setRowCount(1)
        self.viewer.set_email_row(0, email)
        self.assertEqual(self.viewer.email_table.item(0, 0).text(), 'test@example.com')
        self.assertEqual(self.viewer.email_table.item(0, 1).text(), '2025-07-20 12:34')
        self.assertEqual(self.viewer.email_table.item(0, 2).text(), 'Hello')

    def test_set_email_row_missing_fields(self):
        email = {'from': '', 'date': '', 'subject': '', 'uid': '123'}
        self.viewer.email_table.setRowCount(1)
        self.viewer.set_email_row(0, email)
        self.assertEqual(self.viewer.email_table.item(0, 0).text(), '')
        self.assertEqual(self.viewer.email_table.item(0, 1).text(), '')
        self.assertEqual(self.viewer.email_table.item(0, 2).text(), '')

    def test_get_selected_emails_none(self):
        self.viewer.email_table.setRowCount(1)
        self.assertEqual(self.viewer.get_selected_emails(), [])

    def test_get_selected_emails_some(self):
        email = {'from': 'a@b.com', 'date': '2025-07-20', 'subject': 'S', 'uid': '1'}
        self.viewer.emails_data = [email]
        self.viewer.email_table.setRowCount(1)
        self.viewer.set_email_row(0, email)
        self.viewer.email_table.selectRow(0)
        selected = self.viewer.get_selected_emails()
        self.assertEqual(len(selected), 1)
        self.assertEqual(selected[0]['uid'], '1')

    def test_extract_html_body_plain(self):
        class DummyMsg:
            def is_multipart(self): return False
            def get_content_type(self): return 'text/html'
            def get_payload(self, decode): return b'<html>body</html>'
        html = EmailViewer.extract_html_body(DummyMsg())
        self.assertIn('body', html)

    def test_extract_html_body_multipart(self):
        class DummyPart:
            def get_content_type(self): return 'text/html'
            def get_payload(self, decode): return b'<html>body</html>'
        class DummyMsg:
            def is_multipart(self): return True
            def walk(self): return [DummyPart()]
        html = EmailViewer.extract_html_body(DummyMsg())
        self.assertIn('body', html)

    def test_load_emails_handles_exception(self):
        with patch.object(self.viewer, 'client', create=True) as mock_client:
            mock_client.load_credentials.side_effect = Exception('fail')
            self.viewer.load_emails()
            self.assertIn('Error', self.viewer.status_label.text())

class TestFilterDialog(unittest.TestCase):
    def setUp(self):
        self.parent = QWidget()
        self.dialog = FilterDialog(self.parent, [])

    def test_new_filter(self):
        self.dialog.new_filter()
        self.assertEqual(self.dialog.name_edit.text(), '')
        self.assertEqual(self.dialog.action_combo.currentText(), 'Delete')

    def test_update_original_filter_items(self):
        self.dialog.filter_list.addItem('Test: regex')
        self.dialog.update_original_filter_items()
        self.assertIn('Test: regex', self.dialog._original_filter_items)

    def test_clear_filter(self):
        self.dialog.name_edit.setText('abc')
        self.dialog.clear_filter()
        self.assertEqual(self.dialog.name_edit.text(), '')
        self.assertEqual(self.dialog.rule_label.text(), 'Selected Filter: None')

class TestManageRulesDialog(unittest.TestCase):
    def setUp(self):
        class ParentWithSaveRules(QWidget):
            def __init__(self):
                super().__init__()
                self._rules = [{'name': 'R', 'filter': 'F', 'action': 'A'}]
            def load_rules(self):
                return self._rules
            def save_rules(self, rules):
                self._rules = rules
        self.parent = ParentWithSaveRules()
        self.dialog = ManageRulesDialog(self.parent)

    def test_refresh_rule_list(self):
        self.dialog.refresh_rule_list()
        self.assertGreaterEqual(self.dialog.rule_list.count(), 1)

    def test_delete_rule(self):
        self.dialog.rule_list.setCurrentRow(0)
        self.dialog.delete_rule()
        self.assertEqual(self.dialog.rule_list.count(), 0)

class TestDateTableWidgetItem(unittest.TestCase):
    def test_date_str(self):
        item = DateTableWidgetItem('2025-07-20')
        self.assertEqual(item.text(), '2025-07-20')

if __name__ == '__main__':
    unittest.main()
