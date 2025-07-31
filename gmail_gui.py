# Modern GUI Gmail Client - No console, clean interface
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import threading
import os
import smtplib
import imaplib
from email_utils import EmailUtils
import email
import json
import base64
import re  # For regular expression filtering
from pathlib import Path
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.header import decode_header
from datetime import datetime

class GmailGUI:
    def refresh_email_list(self):
        """Refresh the email list in the treeview from self.all_emails"""
        # Clear current display
        for item in self.email_tree.get_children():
            self.email_tree.delete(item)
        # Sort by date descending if no sort order is selected
        emails = self.all_emails
        if not self.last_sort_column:
            def parse_date(email_data):
                date_str = email_data[3]
                try:
                    return datetime.strptime(date_str, "%Y-%m-%d %H:%M")
                except:
                    return datetime.min
            emails = sorted(emails, key=parse_date, reverse=True)
        # Re-populate treeview
        for email_data in emails:
            email_id, from_addr, subject, date_formatted = email_data
            self.email_tree.insert('', 'end', values=(
                email_id,
                from_addr[:50],
                subject[:60],
                date_formatted
            ))
        # Update count labels
        total_count = len(self.all_emails)
        self.email_count_label.config(text=f"INBOX emails: {total_count} (Click column headers to sort)")
        self.update_selection_count()
        self.set_status(f"Email list refreshed - {total_count} emails", "green")
    def __init__(self, root):
        self.root = root
        self.root.title("Gmail Client")
        self.root.geometry("900x700")
        self.root.configure(bg='#f0f0f0')
        
        # Server settings
        self.server_settings = {
            "smtp": {"server": "smtp.gmail.com", "port": 587},
            "imap": {"server": "imap.gmail.com"}
        }
        self.config_file = "gmail_config.json"
        self.rules_file = "gmail_rules.json"  # New file for saved regex rules
        self.username = None
        self.password = None
        
        # Load credentials
        self.load_credentials()
        
        # Create GUI
        self.create_widgets()
        
        # If credentials exist, enable main interface
        if self.username and self.password:
            self.show_main_interface()
        else:
            self.show_login_dialog()
    
    def create_widgets(self):
        # Main frame
        main_frame = ttk.Frame(self.root, padding="20")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Title
        title_label = ttk.Label(main_frame, text="Gmail Client", font=('Arial', 24, 'bold'))
        title_label.grid(row=0, column=0, columnspan=3, pady=(0, 20))
        
        # Status frame
        status_frame = ttk.Frame(main_frame)
        status_frame.grid(row=1, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 20))
        
        self.status_label = ttk.Label(status_frame, text="Ready", foreground='green')
        self.status_label.grid(row=0, column=0, sticky=tk.W)
        
        self.user_label = ttk.Label(status_frame, text="", foreground='blue')
        self.user_label.grid(row=0, column=1, sticky=tk.E)
        
        # Button frame
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=2, column=0, columnspan=3, pady=(0, 20))        # Action buttons
        ttk.Button(button_frame, text="Send Email", command=self.send_email_dialog, width=15).grid(row=0, column=0, padx=5)
        self.load_all_btn = ttk.Button(button_frame, text="Load All Emails", command=self.read_all_emails, width=15)
        self.load_all_btn.grid(row=0, column=1, padx=5)
        ttk.Button(button_frame, text="Delete Email(s)", command=self.delete_email_dialog, width=15).grid(row=0, column=2, padx=5)
        ttk.Button(button_frame, text="Credentials", command=self.manage_credentials, width=15).grid(row=0, column=3, padx=5)
        
        # Second row of buttons for new features
        ttk.Button(button_frame, text="Generate Regex", command=self.generate_regex_from_selection, width=15).grid(row=1, column=0, padx=5, pady=(5,0))
        ttk.Button(button_frame, text="Manage Rules", command=self.show_rules_manager, width=15).grid(row=1, column=1, padx=5, pady=(5,0))
        ttk.Button(button_frame, text="Auto-Delete", command=self.run_auto_delete, width=15).grid(row=1, column=2, padx=5, pady=(5,0))
        
        # Filter frame
        filter_frame = ttk.LabelFrame(main_frame, text="Filter Emails (Python/PCRE RegEx)", padding="10")
        filter_frame.grid(row=3, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
        
        # Filter controls
        ttk.Label(filter_frame, text="Field:").grid(row=0, column=0, sticky=tk.W, padx=(0, 5))
        self.filter_field = ttk.Combobox(filter_frame, values=["From", "Subject", "All"], state="readonly", width=10)
        self.filter_field.set("All")
        self.filter_field.grid(row=0, column=1, padx=5)
        
        ttk.Label(filter_frame, text="RegEx Pattern:").grid(row=0, column=2, sticky=tk.W, padx=(5, 5))
        self.filter_entry = ttk.Entry(filter_frame, width=30)
        self.filter_entry.grid(row=0, column=3, padx=5)
        self.filter_entry.bind('<Return>', lambda e: self.apply_filter())
        
        ttk.Button(filter_frame, text="Apply Filter", command=self.apply_filter, width=12).grid(row=0, column=4, padx=5)
        ttk.Button(filter_frame, text="Clear Filter", command=self.clear_filter, width=12).grid(row=0, column=5, padx=5)
        ttk.Button(filter_frame, text="RegEx Help", command=self.show_regex_help, width=12).grid(row=0, column=6, padx=5)
        
        # Second row of filter controls for selection        ttk.Label(filter_frame, text="Selection:").grid(row=1, column=0, sticky=tk.W, padx=(0, 5), pady=(10, 0))
        ttk.Button(filter_frame, text="Select All", command=lambda: self.select_all_emails(), width=12).grid(row=1, column=1, padx=5, pady=(10, 0))
        ttk.Button(filter_frame, text="Select None", command=lambda: self.select_none_emails(), width=12).grid(row=1, column=2, padx=5, pady=(10, 0))
        
        # Selection count label
        self.selection_count_label = ttk.Label(filter_frame, text="0 emails selected", foreground='blue')
        self.selection_count_label.grid(row=1, column=4, columnspan=2, sticky=tk.W, padx=(10, 0), pady=(10, 0))
          # Email list frame
        list_frame = ttk.LabelFrame(main_frame, text="Emails", padding="10")
        list_frame.grid(row=4, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 20))
        
        # Email count label
        self.email_count_label = ttk.Label(list_frame, text="No emails loaded", foreground='gray')
        self.email_count_label.grid(row=0, column=0, sticky=tk.W, pady=(0, 5))
        # Treeview for emails with multi-selection enabled
        columns = ('ID', 'Subject', 'From', 'Date')
        self.email_tree = ttk.Treeview(list_frame, columns=columns, show='headings', height=15, selectmode='extended')
        # Define headings with sorting
        self.email_tree.heading('ID', text='ID', command=lambda: self.sort_column('ID', False))
        self.email_tree.heading('Subject', text='Subject', command=lambda: self.sort_column('Subject', False))
        self.email_tree.heading('From', text='From', command=lambda: self.sort_column('From', False))
        self.email_tree.heading('Date', text='Date', command=lambda: self.sort_column('Date', False))
        # Configure column widths
        self.email_tree.column('ID', width=60)
        self.email_tree.column('Subject', width=300)
        self.email_tree.column('From', width=200)
        self.email_tree.column('Date', width=150)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.email_tree.yview)
        self.email_tree.configure(yscrollcommand=scrollbar.set)
        
        self.email_tree.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        scrollbar.grid(row=1, column=1, sticky=(tk.N, tk.S))
        
        # Progress bar
        self.progress = ttk.Progressbar(main_frame, mode='indeterminate')
        self.progress.grid(row=5, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=10)
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(4, weight=1)
        list_frame.columnconfigure(0, weight=1)
        list_frame.rowconfigure(1, weight=1)
        status_frame.columnconfigure(1, weight=1)
        
        # Initialize sorting variables
        self.sort_reverse = False
        self.last_sort_column = None
        
        # Initialize filtering variables
        self.all_emails = []  # Store all loaded emails for filtering
        self.filtered_emails = []  # Store currently filtered emails
        self.is_loading = False  # Track loading state
        self.current_filter_pattern = ""  # Track current filter
        self.current_filter_field = "All"  # Track current filter field
        
        # Bind selection change event to update count (after all widgets are created)
        self.email_tree.bind('<<TreeviewSelect>>', lambda e: self.update_selection_count())
        # Bind double-click event to open email in browser
        self.email_tree.bind('<Double-1>', self.open_email_in_browser)
    
    def sort_column(self, col, reverse):
        """Sort treeview contents by column"""
        # If clicking the same column, reverse the sort
        if self.last_sort_column == col:
            reverse = not self.sort_reverse
        else:
            reverse = False
        
        self.sort_reverse = reverse
        self.last_sort_column = col
        
        # Get all items
        items = [(self.email_tree.set(child, col), child) for child in self.email_tree.get_children('')]
        
        # Sort items - handle numeric IDs specially
        if col == 'ID':
            # Sort by numeric ID
            items.sort(key=lambda x: int(x[0]) if x[0].isdigit() else 0, reverse=reverse)
        elif col == 'Date':
            # Sort by date - items with "Unknown" go to end
            def date_sort_key(item):
                date_str = item[0]
                if date_str == "Unknown":
                    return datetime.min if not reverse else datetime.max
                try:
                    return datetime.strptime(date_str, "%Y-%m-%d %H:%M")
                except:
                    return datetime.min if not reverse else datetime.max
            items.sort(key=date_sort_key, reverse=reverse)
        else:
            # Sort alphabetically for From and Subject
            items.sort(key=lambda x: x[0].lower(), reverse=reverse)
        
        # Rearrange items in sorted positions
        for index, (val, child) in enumerate(items):
            self.email_tree.move(child, '', index)

        # Update self.all_emails to match the new sorted order
        sorted_email_data = []
        for child in self.email_tree.get_children(''):
            values = self.email_tree.item(child)['values']
            # values: (ID, Subject, From, Date)
            # Map to (ID, From, Subject, Date) for self.all_emails
            sorted_email_data.append((values[0], values[2], values[1], values[3]))
        self.all_emails = sorted_email_data

        # Update column heading to show sort direction
        for column in ('ID', 'Subject', 'From', 'Date'):
            if column == col:
                direction = ' ↓' if reverse else ' ↑'
                self.email_tree.heading(column, text=column + direction)
            else:
                self.email_tree.heading(column, text=column)
    
    def show_main_interface(self):
        """Enable the main interface when credentials are available"""
        if self.username:
            self.user_label.config(text=f"Logged in as: {self.username}")
            self.set_status("Ready", "green")
    
    def set_status(self, message, color="black"):
        """Update status label"""
        self.status_label.config(text=message, foreground=color)
        self.root.update_idletasks()
    
    def show_progress(self, show=True):
        """Show/hide progress bar"""
        if show:
            self.progress.start()
        else:
            self.progress.stop()
    
    def select_all_emails(self):
        """Select all emails currently visible in the treeview"""
        print("DEBUG: select_all_emails method called successfully!")
        for item in self.email_tree.get_children():
            self.email_tree.selection_add(item)
        self.update_selection_count()
    
    def select_none_emails(self):
        """Clear all selections"""
        self.email_tree.selection_remove(self.email_tree.selection())
        self.update_selection_count()
    
    def invert_selection(self):
        """Invert the current selection"""
        current_selection = set(self.email_tree.selection())
        all_items = set(self.email_tree.get_children())
        
        # Clear current selection
        self.email_tree.selection_remove(self.email_tree.selection())
        
        # Select items that were not previously selected
        for item in all_items - current_selection:
            self.email_tree.selection_add(item)
        
        self.update_selection_count()
    
    def update_selection_count(self):
        """Update the selection count label"""
        # Safety check - ensure the label exists before updating
        if not hasattr(self, 'selection_count_label'):
            return
            
        selected_count = len(self.email_tree.selection())
        total_visible = len(self.email_tree.get_children())
        
        if selected_count == 0:
            self.selection_count_label.config(text="0 emails selected", foreground='blue')
        elif selected_count == total_visible:
            self.selection_count_label.config(text=f"All {selected_count} emails selected", foreground='green')
        else:
            self.selection_count_label.config(text=f"{selected_count} of {total_visible} emails selected", foreground='orange')
    
    def load_credentials(self):
        """Load credentials from config file"""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    config = json.load(f)
                    self.username = config.get('username')
                    self.password = config.get('password')  # Directly load password without decoding
        except Exception as e:
            print(f"Error loading credentials: {e}")
    
    def save_credentials(self):
        """Save credentials to config file"""
        try:
            config = {
                'username': self.username,
                'password': self.password  # Directly save password without encoding
            }
            with open(self.config_file, 'w') as f:
                json.dump(config, f)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save credentials: {e}")
    
    def show_login_dialog(self):
        """Show login dialog"""
        dialog = LoginDialog(self.root, self)
        self.root.wait_window(dialog.dialog)
    
    def send_email_dialog(self):
        """Show send email dialog"""
        if not self.username or not self.password:
            messagebox.showerror("Error", "Please login first")
            return
        
        dialog = SendEmailDialog(self.root, self)
        self.root.wait_window(dialog.dialog)
    
    def delete_email_dialog(self):
        """Show delete email dialog - supports multiple selection"""
        if not self.username or not self.password:
            messagebox.showerror("Error", "Please login first")
            return
        
        selection = self.email_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select one or more emails to delete")
            return
        
        # Get email IDs from selection
        email_ids = []
        for item_id in selection:
            item = self.email_tree.item(item_id)
            email_id = item['values'][0]
            email_ids.append(email_id)
        
        # Confirm deletion
        if len(email_ids) == 1:
            confirm_msg = f"Delete email with ID {email_ids[0]}?"
        else:
            confirm_msg = f"Delete {len(email_ids)} selected emails?\n\nThis action cannot be undone!"
        
        if messagebox.askyesno("Confirm Delete", confirm_msg):
            if len(email_ids) == 1:
                self.delete_email_thread(email_ids[0])
            else:
                self.bulk_delete_emails(email_ids)
    
    def manage_credentials(self):
        """Show credential management dialog"""
        dialog = CredentialDialog(self.root, self)
        self.root.wait_window(dialog.dialog)
    
    def send_email_thread(self, to_email, subject, body):
        """Send email in separate thread"""
        def send():
            self.set_status("Sending email...", "orange")
            self.show_progress(True)
            try:
                # Validate inputs
                if not all([self.username, self.password, to_email, subject]):
                    raise ValueError("All fields are required")
                print(f"DEBUG: Using username: {self.username}")
                print(f"DEBUG: Using password: {self.password}")
                # Create message
                msg = MIMEMultipart()
                msg['From'] = self.username
                msg['To'] = to_email
                msg['Subject'] = subject
                msg.attach(MIMEText(body, 'plain', 'utf-8'))
                # Send email
                with smtplib.SMTP(self.server_settings["smtp"]["server"], 
                                self.server_settings["smtp"]["port"], timeout=10) as server:
                    server.ehlo()
                    if server.has_extn('STARTTLS'):
                        server.starttls()
                        server.ehlo()
                    server.login(self.username, self.password)
                    server.send_message(msg)                
                self.set_status("Email sent successfully!", "green")
                messagebox.showinfo("Success", "Email sent successfully!")
            except smtplib.SMTPAuthenticationError:
                self.set_status("Authentication failed", "red")
                messagebox.showerror("Error", "Authentication failed. You may need an App Password for Gmail.")
            except Exception as e:
                self.set_status("Failed to send email", "red")
                messagebox.showerror("Error", f"Failed to send email: {e}")
            finally:
                self.show_progress(False)
        threading.Thread(target=send, daemon=True).start()
    
    def read_recent_emails(self):
        """Read recent emails (fast) - loads only the 50 most recent"""
        self.read_emails(limit=50)
    
    def read_all_emails(self):
        """Read all emails with confirmation for large inboxes"""
        # Disable the button while loading
        if hasattr(self, 'load_all_btn'):
            self.load_all_btn.config(state='disabled')
        def check_and_load():
            try:
                with imaplib.IMAP4_SSL(self.server_settings["imap"]["server"]) as mail:
                    mail.login(self.username, self.password)
                    # Use EmailUtils to load all emails
                    emails = EmailUtils.load_all_emails(mail, mailbox="INBOX")
                # Sort by date descending if no sort order is selected
                def parse_date(email_data):
                    date_str = email_data[3]
                    try:
                        return datetime.strptime(date_str, "%Y-%m-%d %H:%M")
                    except:
                        return datetime.min
                sorted_emails = emails
                if not self.last_sort_column:
                    sorted_emails = sorted(emails, key=parse_date, reverse=True)
                # Update GUI in main thread
                def update_gui():
                    # Clear existing emails
                    for item in self.email_tree.get_children():
                        self.email_tree.delete(item)
                    self.all_emails = sorted_emails
                    for email_data in sorted_emails:
                        email_id, from_addr, subject, date_formatted = email_data
                        self.email_tree.insert('', 'end', values=(
                            email_id,
                            from_addr[:50],
                            subject[:60],
                            date_formatted
                        ))
                    total_count = len(sorted_emails)
                    self.set_status(f"Loaded {total_count} emails from INBOX", "green")
                    self.email_count_label.config(text=f"INBOX emails: {total_count} (Click column headers to sort)")
                    self.update_selection_count()
                    # Re-enable the button after loading
                    if hasattr(self, 'load_all_btn'):
                        self.load_all_btn.config(state='normal')
                self.root.after(0, update_gui)
            except Exception as e:
                messagebox.showerror("Error", f"Failed to check inbox size: {e}")
                # Re-enable the button if error occurs
                if hasattr(self, 'load_all_btn'):
                    self.load_all_btn.config(state='normal')
        threading.Thread(target=check_and_load, daemon=True).start()
    
    def read_emails(self, limit=None):
        """Read emails in separate thread with optional limit"""
        if self.is_loading:
            messagebox.showwarning("Loading", "Email loading is already in progress")
            return
        def read():
            self.is_loading = True
            self.set_status("Reading emails...", "orange")
            self.show_progress(True)
            try:
                with imaplib.IMAP4_SSL(self.server_settings["imap"]["server"]) as mail:
                    mail.login(self.username, self.password)
                    emails = EmailUtils.load_all_emails(mail, mailbox="INBOX")
                    if limit and limit < len(emails):
                        emails = emails[-limit:]
                    # Sort by date descending if no sort order is selected
                    def parse_date(email_data):
                        date_str = email_data[3]
                        try:
                            return datetime.strptime(date_str, "%Y-%m-%d %H:%M")
                        except:
                            return datetime.min
                    sorted_emails = emails
                    if not self.last_sort_column:
                        sorted_emails = sorted(emails, key=parse_date, reverse=True)
                    # Clear existing emails
                    for item in self.email_tree.get_children():
                        self.email_tree.delete(item)
                    self.all_emails = sorted_emails
                    for email_data in sorted_emails:
                        email_id, from_addr, subject, date_formatted = email_data
                        self.email_tree.insert('', 'end', values=(
                            email_id,
                            from_addr[:50],
                            subject[:60],
                            date_formatted
                        ))
                    email_count = len(sorted_emails)
                    load_type = f"recent {limit}" if limit else "all"
                    status_msg = f"Loaded {email_count} {load_type} emails from INBOX"
                    self.set_status(status_msg, "green")
                    self.email_count_label.config(text=f"INBOX emails: {email_count} {f'({load_type})' if limit else ''} (Click column headers to sort)")
                    self.update_selection_count()
            except imaplib.IMAP4.error as e:
                error_msg = str(e)
                if "Application-specific password required" in error_msg:
                    self.set_status("App Password required", "red")
                    messagebox.showerror("Error", "Gmail App Password required. Please update credentials.")
                else:
                    self.set_status("IMAP error", "red")
                    messagebox.showerror("Error", f"IMAP error: {e}")
            except Exception as e:
                self.set_status("Failed to read emails", "red")
                messagebox.showerror("Error", f"Failed to read emails: {e}")
            finally:
                self.show_progress(False)
                self.is_loading = False
        threading.Thread(target=read, daemon=True).start()
    
    def delete_email_thread(self, email_id):
        """Delete email in separate thread - OPTIMIZED VERSION"""
        def delete():
            self.set_status("Deleting email...", "orange")
            self.show_progress(True)
            try:
                with imaplib.IMAP4_SSL(self.server_settings["imap"]["server"]) as mail:
                    mail.login(self.username, self.password)
                    mail.select("inbox")
                    
                    # Convert email_id to string first, then to bytes for IMAP
                    email_id_str = str(email_id)
                    email_id_bytes = email_id_str.encode()
                    
                    # Delete email using bytes
                    mail.store(email_id_bytes, '+FLAGS', '\\Deleted')
                    mail.expunge()
                
                self.set_status("Email deleted successfully", "green")
                
                # Remove from stored emails immediately (much faster than reloading)
                self.all_emails = [email for email in self.all_emails if email[0] != email_id_str]
                # Refresh the email list in the GUI
                self.refresh_email_list()
                messagebox.showinfo("Success", "Email deleted successfully!")
                
            except Exception as e:
                self.set_status("Failed to delete email", "red")
                messagebox.showerror("Error", f"Failed to delete email: {e}")
            finally:
                self.show_progress(False)
        
        threading.Thread(target=delete, daemon=True).start()
    
    #
    def bulk_delete_emails(self, email_ids):
        """Delete multiple emails in separate thread"""
        def delete():
            self.set_status(f"Deleting {len(email_ids)} emails...", "orange")
            self.show_progress(True)
            deleted_count = 0
            failed_count = 0
            try:
                with imaplib.IMAP4_SSL(self.server_settings["imap"]["server"]) as mail:
                    mail.login(self.username, self.password)
                    mail.select("inbox")
                    for i, email_id in enumerate(email_ids):
                        try:
                            # Update progress every 10 emails
                            if i % 10 == 0:
                                self.set_status(f"Deleting emails... {i+1}/{len(email_ids)}", "orange")
                                self.root.update_idletasks()
                            # Convert email_id to string first, then to bytes for IMAP
                            email_id_str = str(email_id)
                            email_id_bytes = email_id_str.encode()
                            # Delete email using bytes
                            mail.store(email_id_bytes, '+FLAGS', '\\Deleted')
                            deleted_count += 1
                        except Exception as e:
                            print(f"Failed to delete email {email_id}: {e}")
                            failed_count += 1
                    # Expunge to permanently delete
                    mail.expunge()
                # Remove deleted emails from stored emails immediately
                deleted_ids_str = [str(email_id) for email_id in email_ids]
                self.all_emails = [email for email in self.all_emails if email[0] not in deleted_ids_str]
                # Refresh the email list in the GUI
                self.refresh_email_list()
                # Show results
                result_msg = f"Bulk deletion completed!\n\nDeleted: {deleted_count} emails"
                if failed_count > 0:
                    result_msg += f"\nFailed: {failed_count} emails"
                self.set_status(f"{deleted_count} emails deleted successfully", "green")
                messagebox.showinfo("Bulk Delete Complete", result_msg)
            except Exception as e:
                self.set_status("Failed to delete emails", "red")
                messagebox.showerror("Error", f"Failed to delete emails: {e}")
            finally:
                self.show_progress(False)
        threading.Thread(target=delete, daemon=True).start()
    
    def apply_filter(self):
        """Apply regex filter to loaded emails"""
        pattern = self.filter_entry.get().strip()
        field = self.filter_field.get()
        if not pattern:
            self.clear_filter()
            return
        try:
            # Clear current display
            for item in self.email_tree.get_children():
                self.email_tree.delete(item)
            filtered_count = 0
            regex = re.compile(pattern, re.IGNORECASE)
            for email_data in self.all_emails:
                email_id, from_addr, subject, date_formatted = email_data
                match_found = False
                if field == "From":
                    match_found = regex.search(from_addr)
                elif field == "Subject":
                    # Use regex search for Subject (case-insensitive)
                    match_found = regex.search(subject)
                else:  # "All" - match regex for both From and Subject
                    match_found = regex.search(from_addr) or regex.search(subject)
                if match_found:
                    self.email_tree.insert('', 'end', values=(
                        email_id,
                        from_addr[:50],
                        subject[:60],
                        date_formatted
                    ))
                    filtered_count += 1
            total_count = len(self.all_emails)
            self.set_status(f"Filter applied: {filtered_count}/{total_count} emails match", "blue")
            self.email_count_label.config(text=f"Filtered: {filtered_count}/{total_count} emails (Pattern: {pattern})")
            self.update_selection_count()  # Update selection count after filter
        except re.error as e:
            messagebox.showerror("RegEx Error", f"Invalid regular expression: {e}")
            self.set_status("Invalid regex pattern", "red")
    
    def clear_filter(self):
        """Clear filter and show all emails"""
        self.filter_entry.delete(0, tk.END)
        
        # Clear current display
        for item in self.email_tree.get_children():
            self.email_tree.delete(item)
        
        # Restore all emails
        for email_data in self.all_emails:
            email_id, from_addr, subject, date_formatted = email_data
            self.email_tree.insert('', 'end', values=(
                email_id,
                from_addr[:50],
                subject[:60],
                date_formatted
            ))
          # Update status
        total_count = len(self.all_emails)
        self.set_status(f"Filter cleared - showing all {total_count} emails", "green")
        self.email_count_label.config(text=f"INBOX emails: {total_count} (Click column headers to sort)")
        self.update_selection_count()  # Update selection count after clearing filter
    
    def show_regex_help(self):
        """Show regex help dialog"""
        help_text = """Python Regular Expression (PCRE) Quick Reference:

BASIC PATTERNS:
.          Any character except newline
*          0 or more of previous character
+          1 or more of previous character
?          0 or 1 of previous character
^          Start of string
$          End of string

CHARACTER CLASSES:
[abc]      Any of a, b, or c
[a-z]      Any lowercase letter
[A-Z]      Any uppercase letter
[0-9]      Any digit
\\d         Any digit (0-9)
\\w         Any word character (a-z, A-Z, 0-9, _)
\\s         Any whitespace character

EXAMPLES:
gmail\\.com              Emails from Gmail
^Amazon                 Subject starting with "Amazon"
@(gmail|yahoo)\\.com    Gmail or Yahoo addresses
\\d{4}                   4 consecutive digits
(urgent|important)      Contains "urgent" or "important"
^(?!.*spam)             Does NOT contain "spam"

MODIFIERS:
Filters are case-insensitive by default.
Use (?-i) at start of pattern for case-sensitive."""
        
        messagebox.showinfo("Regular Expression Help", help_text)
    
    def load_saved_rules(self):
        """Load saved regex rules from file"""
        try:
            if os.path.exists(self.rules_file):
                with open(self.rules_file, 'r') as f:
                    return json.load(f)
            return []
        except Exception as e:
            print(f"Error loading rules: {e}")
            return []
    
    def save_rules(self, rules):
        """Save regex rules to file"""
        try:
            with open(self.rules_file, 'w') as f:
                json.dump(rules, f, indent=2)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save rules: {e}")
    
    def generate_regex_from_selection(self):
        """Generate regex patterns from selected emails"""
        selection = self.email_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select one or more emails to generate regex from")
            return
        
        if len(selection) == 1:
            messagebox.showwarning("Warning", "Please select at least 2 emails to generate a meaningful pattern")
            return
        
        # Collect data from selected emails
        selected_emails = []
        for item_id in selection:
            item = self.email_tree.item(item_id)
            values = item['values']
            if len(values) >= 3:
                selected_emails.append({
                    'from': values[1],
                    'subject': values[2],
                    'id': values[0]
                })
        
        # Show dialog to create regex rule
        self.show_regex_generator_dialog(selected_emails)
    
    def find_common_patterns(self, emails, field):
        """Find common patterns in email field (from or subject)"""
        patterns = []
        values = [email[field] for email in emails]
        
        # Extract domains from email addresses
        if field == 'from':
            domains = []
            for addr in values:
                if '@' in addr:
                    domain = addr.split('@')[-1].split('>')[0].strip()
                    domains.append(domain)
            if len(set(domains)) == 1 and domains:  # All same domain
                patterns.append(f"@{re.escape(domains[0])}")
        
        # Find common words/phrases
        if field == 'subject':
            # Find words that appear in multiple subjects
            all_words = []
            for subject in values:
                words = re.findall(r'\b\w+\b', subject.lower())
                all_words.extend(words)
            
            word_counts = {}
            for word in all_words:
                word_counts[word] = word_counts.get(word, 0) + 1
            
            # Find words that appear in at least half the emails
            threshold = len(values) // 2 + 1
            common_words = [word for word, count in word_counts.items() if count >= threshold and len(word) > 2]
            
            if common_words:
                # Create pattern with most common words
                pattern = '|'.join(re.escape(word) for word in common_words[:3])
                patterns.append(f"({pattern})")
        
        return patterns

    def show_regex_generator_dialog(self, selected_emails):
        """Show dialog to generate and save regex rules from selected emails"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Generate Regex Rule")
        dialog.geometry("660x550")
        dialog.resizable(True, True)
        dialog.grab_set()
        
        # Main frame
        main_frame = ttk.Frame(dialog, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Title
        ttk.Label(main_frame, text="Generate Automatic Deletion Rule", font=('Arial', 14, 'bold')).pack(pady=(0, 10))
        
        # Selected emails info
        info_frame = ttk.LabelFrame(main_frame, text="Selected Emails", padding="10")
        info_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(info_frame, text=f"Number of selected emails: {len(selected_emails)}").pack(anchor=tk.W)
        
        # Show first few emails as examples
        for i, email in enumerate(selected_emails[:3]):
            ttk.Label(info_frame, text=f"• From: {email['from'][:50]}", font=('Courier', 9)).pack(anchor=tk.W)
            ttk.Label(info_frame, text=f"  Subject: {email['subject'][:50]}", font=('Courier', 9)).pack(anchor=tk.W)
            if i < len(selected_emails) - 1:
                ttk.Label(info_frame, text="").pack()  # Spacer
        
        if len(selected_emails) > 3:
            ttk.Label(info_frame, text=f"... and {len(selected_emails) - 3} more emails").pack(anchor=tk.W)
        
        # Pattern generation
        pattern_frame = ttk.LabelFrame(main_frame, text="Generated Patterns", padding="10")
        pattern_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        # Field selection
        field_frame = ttk.Frame(pattern_frame)
        field_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(field_frame, text="Target Field:").pack(side=tk.LEFT)
        field_var = tk.StringVar(value="from")
        ttk.Radiobutton(field_frame, text="From", variable=field_var, value="from").pack(side=tk.LEFT, padx=(10, 5))
        ttk.Radiobutton(field_frame, text="Subject", variable=field_var, value="subject").pack(side=tk.LEFT, padx=5)
        
        # Pattern suggestions
        suggestion_frame = ttk.Frame(pattern_frame)
        suggestion_frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(suggestion_frame, text="Suggested Patterns:").pack(anchor=tk.W)
        
        pattern_listbox = tk.Listbox(suggestion_frame, height=6)
        pattern_listbox.pack(fill=tk.BOTH, expand=True, pady=(5, 10))
        
        # Custom pattern entry
        ttk.Label(pattern_frame, text="Custom Pattern (RegEx):").pack(anchor=tk.W)
        pattern_entry = ttk.Entry(pattern_frame, width=50)
        pattern_entry.pack(fill=tk.X, pady=(5, 10))
        
        # Rule name
        ttk.Label(pattern_frame, text="Rule Name:").pack(anchor=tk.W)
        name_entry = ttk.Entry(pattern_frame, width=50)
        name_entry.pack(fill=tk.X, pady=(5, 10))
        
        def update_suggestions():
            """Update pattern suggestions based on selected field"""
            field = field_var.get()
            pattern_listbox.delete(0, tk.END)
            # Correct field mapping: 'from' uses email, 'subject' uses subject
            if field == 'from':
                # Add domain-based patterns
                domains = set()
                for email in selected_emails:
                    if '@' in email['subject']:
                        domain = email['subject'].split('@')[-1].split('>')[0].strip()
                        domains.add(domain)
                for domain in sorted(domains):
                    pattern_listbox.insert(tk.END, f"@{re.escape(domain)}")
                # Add sender name patterns
                senders = set()
                for email in selected_emails:
                    from_field = email['subject']
                    if '<' in from_field:
                        name_part = from_field.split('<')[0].strip().strip('"')
                        if name_part and len(name_part) > 2:
                            senders.add(name_part)
                for sender in sorted(senders):
                    if len(sender) > 2:
                        pattern_listbox.insert(tk.END, re.escape(sender))
            else:  # subject
                # Suggest plain text subject phrases
                subject_phrases = set()
                for email in selected_emails:
                    subject = email['subject'].strip()
                    if subject and len(subject) > 2:
                        subject_phrases.add(subject)
                for phrase in sorted(subject_phrases):
                    pattern_listbox.insert(tk.END, phrase)
        
        def on_pattern_select(event):
            """When a pattern is selected from the list"""
            selection = pattern_listbox.curselection()
            if selection:
                pattern = pattern_listbox.get(selection[0])
                pattern_entry.delete(0, tk.END)
                pattern_entry.insert(0, pattern)
        
        def test_pattern():
            """Test the current pattern against all emails"""
            pattern = pattern_entry.get().strip()
            if not pattern:
                messagebox.showwarning("Warning", "Please enter a pattern to test")
                return
            try:
                regex = re.compile(pattern, re.IGNORECASE)
                field = field_var.get()
                # Use all emails for testing
                all_emails = self.all_emails if hasattr(self, 'all_emails') else []
                matches = []
                for email_data in all_emails:
                    email_id, from_addr, subject, date_formatted = email_data
                    test_value = subject if field == 'from' else from_addr
                    if regex.search(test_value):
                        matches.append((email_id, from_addr, subject, date_formatted, test_value))
                result_text = f"Pattern matches {len(matches)}/{len(all_emails)} emails:\n\n"
                for match in matches[:5]:  # Show first 5 matches
                    result_text += f"\u2022 {match[4][:60]}\n"
                if len(matches) > 5:
                    result_text += f"... and {len(matches) - 5} more"
                messagebox.showinfo("Pattern Test Result", result_text)
            except re.error as e:
                messagebox.showerror("RegEx Error", f"Invalid pattern: {e}")
        
        def save_rule():
            """Save the rule and close dialog"""
            pattern = pattern_entry.get().strip()
            name = name_entry.get().strip()
            field = field_var.get()
            
            if not pattern:
                messagebox.showwarning("Warning", "Please enter a pattern")
                return
            
            if not name:
                messagebox.showwarning("Warning", "Please enter a rule name")
                return
            
            # Test pattern validity
            try:
                re.compile(pattern, re.IGNORECASE)
            except re.error as e:
                messagebox.showerror("RegEx Error", f"Invalid pattern: {e}")
                return
            
            # Load existing rules
            rules = self.load_saved_rules()
            
            # Add new rule
            new_rule = {
                'name': name,
                'pattern': pattern,
                'field': field,
                'created': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'sample_emails': len(selected_emails)
            }
            
            rules.append(new_rule)
            
            # Save rules
            self.save_rules(rules)
            
            messagebox.showinfo("Success", f"Rule '{name}' saved successfully!")
            dialog.destroy()
        
        # Bind events
        field_var.trace('w', lambda *args: update_suggestions())
        pattern_listbox.bind('<<ListboxSelect>>', on_pattern_select)
        
        # Buttons
        button_frame = ttk.Frame(pattern_frame)
        button_frame.pack(fill=tk.X, pady=(10, 0))
        
        ttk.Button(button_frame, text="Test Pattern", command=test_pattern).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(button_frame, text="Save Rule", command=save_rule).pack(side=tk.RIGHT, padx=(5, 0))
        ttk.Button(button_frame, text="Cancel", command=dialog.destroy).pack(side=tk.RIGHT)
        
        # Initialize suggestions
        update_suggestions()
        
        # Set default rule name
        name_entry.insert(0, f"Auto-Rule-{len(self.load_saved_rules()) + 1}")

    def show_rules_manager(self):
        def edit_rule():
            """Edit selected rule"""
            selection = rules_tree.selection()
            if not selection:
                messagebox.showwarning("Warning", "Please select a rule to edit")
                return
            item = rules_tree.item(selection[0])
            rule_name = item['values'][0]
            # Find the rule
            rules = self.load_saved_rules()
            rule = None
            for r in rules:
                if r['name'] == rule_name:
                    rule = r
                    break
            if not rule:
                messagebox.showerror("Error", f"Rule '{rule_name}' not found")
                return
            # Edit dialog
            edit_dialog = tk.Toplevel(dialog)
            edit_dialog.title(f"Edit Rule: {rule_name}")
            edit_dialog.geometry("500x300")
            edit_dialog.grab_set()
            frame = ttk.Frame(edit_dialog, padding="20")
            frame.pack(fill=tk.BOTH, expand=True)
            ttk.Label(frame, text="Rule Name:").grid(row=0, column=0, sticky=tk.W)
            name_entry = ttk.Entry(frame, width=40)
            name_entry.grid(row=0, column=1, pady=5)
            name_entry.insert(0, rule['name'])
            ttk.Label(frame, text="Pattern (RegEx):").grid(row=1, column=0, sticky=tk.W)
            pattern_entry = ttk.Entry(frame, width=40)
            pattern_entry.grid(row=1, column=1, pady=5)
            pattern_entry.insert(0, rule['pattern'])
            ttk.Label(frame, text="Field:").grid(row=2, column=0, sticky=tk.W)
            field_var = tk.StringVar(value=rule['field'])
            field_combo = ttk.Combobox(frame, textvariable=field_var, values=["from", "subject", "all"], state="readonly", width=10)
            field_combo.grid(row=2, column=1, pady=5)
            def save_edit():
                new_name = name_entry.get().strip()
                new_pattern = pattern_entry.get().strip()
                new_field = field_var.get()
                if not new_name or not new_pattern:
                    messagebox.showwarning("Warning", "Name and pattern are required")
                    return
                try:
                    re.compile(new_pattern, re.IGNORECASE)
                except re.error as e:
                    messagebox.showerror("RegEx Error", f"Invalid pattern: {e}")
                    return
                # Update rule
                rule['name'] = new_name
                rule['pattern'] = new_pattern
                rule['field'] = new_field
                self.save_rules(rules)
                load_rules_list()
                messagebox.showinfo("Success", f"Rule '{new_name}' updated.")
                edit_dialog.destroy()
            ttk.Button(frame, text="Save", command=save_edit).grid(row=3, column=1, sticky=tk.E, pady=10)
            ttk.Button(frame, text="Cancel", command=edit_dialog.destroy).grid(row=3, column=0, sticky=tk.W, pady=10)
        """Show dialog to manage saved regex rules"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Manage Auto-Delete Rules")
        dialog.geometry("840x600")
        dialog.resizable(True, True)
        dialog.grab_set()
        
        # Main frame
        main_frame = ttk.Frame(dialog, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Title
        ttk.Label(main_frame, text="Auto-Delete Rules Manager", font=('Arial', 14, 'bold')).pack(pady=(0, 10))
        
        # Rules list
        list_frame = ttk.LabelFrame(main_frame, text="Saved Rules", padding="10")
        list_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        # Treeview for rules
        columns = ('Name', 'Field', 'Pattern', 'Created')
        rules_tree = ttk.Treeview(list_frame, columns=columns, show='headings', height=15)
        
        rules_tree.heading('Name', text='Rule Name')
        rules_tree.heading('Field', text='Target Field')
        rules_tree.heading('Pattern', text='Pattern')
        rules_tree.heading('Created', text='Created')
        
        rules_tree.column('Name', width=150)
        rules_tree.column('Field', width=80)
        rules_tree.column('Pattern', width=200)
        rules_tree.column('Created', width=120)
        
        # Scrollbar for rules
        rules_scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=rules_tree.yview)
        rules_tree.configure(yscrollcommand=rules_scrollbar.set)
        
        rules_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        rules_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        def load_rules_list():
            """Load and display rules in the treeview"""
            # Clear existing items
            for item in rules_tree.get_children():
                rules_tree.delete(item)
            
            # Load and display rules
            rules = self.load_saved_rules()
            for rule in rules:
                rules_tree.insert('', 'end', values=(
                    rule['name'],
                    rule['field'].title(),
                    rule['pattern'][:50] + ('...' if len(rule['pattern']) > 50 else ''),
                    rule.get('created', 'unknown')
                ))
        
        def delete_rule():
            """Delete selected rule"""
            selection = rules_tree.selection()
            if not selection:
                messagebox.showwarning("Warning", "Please select a rule to delete")
                return
            
            item = rules_tree.item(selection[0])
            rule_name = item['values'][0]
            
            if messagebox.askyesno("Confirm Delete", f"Delete rule '{rule_name}'?"):
                rules = self.load_saved_rules()
                rules = [rule for rule in rules if rule['name'] != rule_name]
                self.save_rules(rules)
                load_rules_list()
                messagebox.showinfo("Success", f"Rule '{rule_name}' deleted")
        
        def test_rule():
            """Test selected rule against current emails"""
            selection = rules_tree.selection()
            if not selection:
                messagebox.showwarning("Warning", "Please select a rule to test")
                return
            
            if not self.all_emails:
                messagebox.showwarning("Warning", "Please load emails first")
                return
            
            item = rules_tree.item(selection[0])
            rule_name = item['values'][0]
            
            # Find the rule
            rules = self.load_saved_rules()
            rule = None
            for r in rules:
                if r['name'] == rule_name:
                    rule = r
                    break
            
            if not rule:
                messagebox.showerror("Error", "Rule not found")
                return
            
            try:
                regex = re.compile(rule['pattern'], re.IGNORECASE)
                field = rule['field']
                
                matches = []
                for email_data in self.all_emails:
                    email_id, subject, from_addr, date_formatted = email_data
                    target_text = from_addr if field == 'from' else subject
                    if regex.search(target_text):
                        matches.append(email_data)
                result_text = f"Rule '{rule_name}' would delete {len(matches)} out of {len(self.all_emails)} emails:\n\n"
                for i, email_data in enumerate(matches[:5]):
                    result_text += f"• From: {email_data[2][:40]}\n"
                    result_text += f"  Subject: {email_data[1][:40]}\n\n"
                if len(matches) > 5:
                    result_text += f"... and {len(matches) - 5} more emails"
                messagebox.showinfo("Rule Test Result", result_text)
                
            except re.error as e:
                messagebox.showerror("RegEx Error", f"Invalid pattern in rule: {e}")
        
        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=(10, 0))
        ttk.Button(button_frame, text="Test Rule", command=test_rule).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(button_frame, text="Edit Rule", command=edit_rule).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Delete Rule", command=delete_rule).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Refresh", command=load_rules_list).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Close", command=dialog.destroy).pack(side=tk.RIGHT)
        
        # Load initial rules
        load_rules_list()
    
    def run_auto_delete(self):
        """Run automatic deletion based on saved rules (robust field matching)"""
        if not self.all_emails:
            messagebox.showinfo("Info", "No emails loaded to process.")
            return
        rules = self.load_saved_rules()
        if not rules:
            messagebox.showinfo("Info", "No auto-delete rules found.")
            return

        def on_rules_selected(selected_rules):
            if not selected_rules:
                messagebox.showinfo("Info", "No rules selected.")
                return
            # Build list of email IDs to delete
            emails_to_delete = set()
            for rule in selected_rules:
                pattern = rule['pattern']
                field = rule['field'].lower()
                try:
                    regex = re.compile(pattern, re.IGNORECASE)
                except re.error:
                    continue
                for email_data in self.all_emails:
                    # email_data: (id, subject, from_addr, date_formatted)
                    if field == 'from':
                        target = email_data[2]
                    elif field == 'subject':
                        target = email_data[1]
                    elif field == 'all':
                        target = f"{email_data[2]} {email_data[1]}"
                    else:
                        # fallback: try both
                        target = f"{email_data[2]} {email_data[1]}"
                    if regex.search(target):
                        emails_to_delete.add(email_data[0])
            if not emails_to_delete:
                messagebox.showinfo("Info", "No emails match the selected rules.")
                return
            # Confirm deletion
            if messagebox.askyesno("Confirm Auto-Delete", f"Delete {len(emails_to_delete)} emails matching selected rules? This cannot be undone."):
                self.bulk_delete_emails(list(emails_to_delete))
        self.show_auto_delete_dialog(rules, on_rules_selected)

    def show_auto_delete_dialog(self, rules, callback=None):
        """Show dialog to select rules for automatic deletion and call callback with selected rules"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Auto-Delete Emails")
        dialog.geometry("600x400")
        dialog.resizable(True, True)
        dialog.grab_set()
        
        # Main frame
        main_frame = ttk.Frame(dialog, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Title
        ttk.Label(main_frame, text="Select Rules for Auto-Delete", font=('Arial', 14, 'bold')).pack(pady=(0, 10))
        
        # Warning
        warning_frame = ttk.Frame(main_frame)
        warning_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(warning_frame, text="⚠️ WARNING: This will permanently delete emails!", 
                 foreground='red', font=('Arial', 12, 'bold')).pack()
        ttk.Label(warning_frame, text="Please review the rules carefully before proceeding.").pack()
        
        # Rules selection
        rules_frame = ttk.LabelFrame(main_frame, text="Available Rules", padding="10")
        rules_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        # Checkboxes for rules
        rule_vars = {}
        rule_widgets = []
        canvas = tk.Canvas(rules_frame)
        scrollbar = ttk.Scrollbar(rules_frame, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        # Add Select All checkbox at the top
        select_all_var = tk.BooleanVar(value=False)
        rule_vars = {}
        rule_widgets = []
        updating_select_all = False  # Prevent recursive updates
        def on_select_all():
            nonlocal updating_select_all
            updating_select_all = True
            # Set all rule checkboxes to match Select All
            for var in rule_vars.values():
                var.set(select_all_var.get())
            updating_select_all = False
        select_all_cb = ttk.Checkbutton(scrollable_frame, text="Select All", variable=select_all_var, command=on_select_all)
        select_all_cb.grid(row=0, column=0, sticky=tk.W, pady=2)

        # Add rule checkboxes below
        for i, rule in enumerate(rules):
            var = tk.BooleanVar(value=False)
            # Swap subject and from if needed for display
            field_label = rule['field']
            display_name = rule['name']
            # If the rule is for 'from', show the email address as name
            if field_label.lower() == 'from' and 'Filter' in display_name:
                # Try to extract email from rule['pattern'] if possible
                display_name = rule['pattern'] if '@' in rule['pattern'] else display_name
            cb = ttk.Checkbutton(scrollable_frame, text=f"{display_name} ({field_label})", variable=var)
            cb.grid(row=i+1, column=0, sticky=tk.W, pady=2)
            rule_vars[i] = var
            rule_widgets.append(cb)

        # Keep Select All in sync with individual rule selections
        def update_select_all(*args):
            nonlocal updating_select_all
            if updating_select_all:
                return
            all_selected = all(var.get() for var in rule_vars.values()) if rule_vars else False
            select_all_var.set(all_selected)
        for var in rule_vars.values():
            var.trace_add('write', update_select_all)

        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=(10, 0))
        
        def on_confirm():
            selected_rules = [rules[i] for i, var in rule_vars.items() if var.get()]
            dialog.destroy()
            if callback:
                callback(selected_rules)
        
        ttk.Button(button_frame, text="Delete Matching Emails", command=on_confirm).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(button_frame, text="Cancel", command=dialog.destroy).pack(side=tk.RIGHT)

    def open_email_in_browser(self, event):
        """Open selected email in the default web browser as HTML"""
        import webbrowser
        import tempfile
        selection = self.email_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select an email to view")
            return
        item_id = selection[0]
        # Get the displayed ID from the first column of the selected row
        displayed_id = self.email_tree.item(item_id)['values'][0]
        # Find the email data in self.all_emails using the displayed ID
        email_data = next((e for e in self.all_emails if str(e[0]) == str(displayed_id)), None)
        if not email_data:
            messagebox.showerror("Error", "Email data not found")
            return
        # Try to get the raw email from the server
        try:
            with imaplib.IMAP4_SSL(self.server_settings["imap"]["server"]) as mail:
                mail.login(self.username, self.password)
                mail.select("inbox")
                typ, msg_data = mail.fetch(str(displayed_id), '(RFC822)')
                if typ != 'OK' or not msg_data:
                    raise Exception("Failed to fetch email")
                raw_email = msg_data[0][1]
                import email
                msg = email.message_from_bytes(raw_email)
                html_content = None
                for part in msg.walk():
                    if part.get_content_type() == "text/html":
                        html_content = part.get_payload(decode=True).decode(part.get_content_charset() or 'utf-8', errors='replace')
                        break
                if not html_content:
                    # Fallback: use plain text and convert to HTML
                    for part in msg.walk():
                        if part.get_content_type() == "text/plain":
                            text_content = part.get_payload(decode=True).decode(part.get_content_charset() or 'utf-8', errors='replace')
                            html_content = f"<pre>{text_content}</pre>"
                            break
                if not html_content:
                    html_content = "<p>No content available.</p>"
                # Write to temp HTML file
                with tempfile.NamedTemporaryFile('w', delete=False, suffix='.html', encoding='utf-8') as f:
                    f.write(html_content)
                    temp_path = f.name
                webbrowser.open(temp_path)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to render email: {e}")

# Simple Dialog Classes for basic functionality

class LoginDialog:
    def __init__(self, parent, app):
        self.app = app
        self.dialog = tk.Toplevel(parent)
        self.dialog.title("Gmail Login")
        self.dialog.geometry("400x300")
        self.dialog.resizable(False, False)
        self.dialog.grab_set()
        
        # Center the dialog
        self.dialog.transient(parent)
        
        main_frame = ttk.Frame(self.dialog, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Title
        ttk.Label(main_frame, text="Gmail Login", font=('Arial', 16, 'bold')).pack(pady=(0, 20))
        
        # Username
        ttk.Label(main_frame, text="Email:").pack(anchor=tk.W)
        self.username_entry = ttk.Entry(main_frame, width=40)
        self.username_entry.pack(pady=(5, 10), fill=tk.X)
        
        # Password
        ttk.Label(main_frame, text="Password (App Password recommended):").pack(anchor=tk.W)
        self.password_entry = ttk.Entry(main_frame, show="*", width=40)
        self.password_entry.pack(pady=(5, 10), fill=tk.X)
        
        # Info
        info_text = ("For Gmail, use an App Password instead of your regular password.\n"
                    "Go to Google Account Settings → Security → App Passwords to create one.")
        ttk.Label(main_frame, text=info_text, foreground='blue', font=('Arial', 9)).pack(pady=(0, 20))
        
        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X)
        
        ttk.Button(button_frame, text="Login", command=self.save_credentials).pack(side=tk.RIGHT, padx=(5, 0))
        ttk.Button(button_frame, text="Cancel", command=self.dialog.destroy).pack(side=tk.RIGHT)
        
        # Focus on username entry
        self.username_entry.focus()
    
    def save_credentials(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get()
        
        if not username or not password:
            messagebox.showerror("Error", "Please enter both email and password")
            return
        
        self.app.username = username
        self.app.password = password
        self.app.save_credentials()
        self.app.show_main_interface()
        self.dialog.destroy()


class SendEmailDialog:
    def __init__(self, parent, app):
        self.app = app
        self.dialog = tk.Toplevel(parent)
        self.dialog.title("Send Email")
        self.dialog.geometry("600x500")
        self.dialog.resizable(True, True)
        self.dialog.grab_set()
        
        main_frame = ttk.Frame(self.dialog, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Title
        ttk.Label(main_frame, text="Send Email", font=('Arial', 16, 'bold')).pack(pady=(0, 20))
        
        # To
        ttk.Label(main_frame, text="To:").pack(anchor=tk.W)
        self.to_entry = ttk.Entry(main_frame, width=50)
        self.to_entry.pack(pady=(5, 10), fill=tk.X)
        
        # Subject
        ttk.Label(main_frame, text="Subject:").pack(anchor=tk.W)
        self.subject_entry = ttk.Entry(main_frame, width=50)
        self.subject_entry.pack(pady=(5, 10), fill=tk.X)
        
        # Body
        ttk.Label(main_frame, text="Message:").pack(anchor=tk.W)
        self.body_text = tk.Text(main_frame, height=15, width=50)
        self.body_text.pack(pady=(5, 10), fill=tk.BOTH, expand=True)
        
        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=(10, 0))
        
        ttk.Button(button_frame, text="Send", command=self.send_email).pack(side=tk.RIGHT, padx=(5, 0))
        ttk.Button(button_frame, text="Cancel", command=self.dialog.destroy).pack(side=tk.RIGHT)
        
        # Focus on to entry
        self.to_entry.focus()
    
    def send_email(self):
        to_email = self.to_entry.get().strip()
        subject = self.subject_entry.get().strip()
        body = self.body_text.get('1.0', tk.END).strip()
        
        if not all([to_email, subject, body]):
            messagebox.showerror("Error", "Please fill in all fields")
            return
        
        self.app.send_email_thread(to_email, subject, body)
        self.dialog.destroy()


class CredentialDialog:
    def __init__(self, parent, app):
        self.app = app
        self.dialog = tk.Toplevel(parent)
        self.dialog.title("Manage Credentials")
        self.dialog.geometry("500x400")
        self.dialog.resizable(False, False)
        self.dialog.grab_set()
        
        main_frame = ttk.Frame(self.dialog, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Title
        ttk.Label(main_frame, text="Manage Gmail Credentials", font=('Arial', 16, 'bold')).pack(pady=(0, 20))
        
        # Current credentials
        current_frame = ttk.LabelFrame(main_frame, text="Current Credentials", padding="10")
        current_frame.pack(fill=tk.X, pady=(0, 20))
        
        ttk.Label(current_frame, text=f"Email: {self.app.username or 'Not set'}").pack(anchor=tk.W)
        ttk.Label(current_frame, text=f"Password: {'Set' if self.app.password else 'Not set'}").pack(anchor=tk.W)
        
        # New credentials
        new_frame = ttk.LabelFrame(main_frame, text="Update Credentials", padding="10")
        new_frame.pack(fill=tk.X, pady=(0, 20))
        
        ttk.Label(new_frame, text="Email:").pack(anchor=tk.W)
        self.username_entry = ttk.Entry(new_frame, width=40)
        self.username_entry.pack(pady=(5, 10), fill=tk.X)
        if self.app.username:
            self.username_entry.insert(0, self.app.username)
        
        ttk.Label(new_frame, text="Password (App Password recommended):").pack(anchor=tk.W)
        self.password_entry = ttk.Entry(new_frame, show="*", width=40)
        self.password_entry.pack(pady=(5, 10), fill=tk.X)
        
        # App Password info
        info_frame = ttk.LabelFrame(main_frame, text="Gmail App Password Setup", padding="10")
        info_frame.pack(fill=tk.X, pady=(0, 20))
        
        info_text = ("1. Go to your Google Account settings\n"
                    "2. Navigate to Security → 2-Step Verification\n"
                    "3. Scroll down to App Passwords\n"
                    "4. Generate a new app password for 'Mail'\n"
                    "5. Use the generated 16-character password here")
        
        ttk.Label(info_frame, text=info_text, font=('Arial', 9)).pack(anchor=tk.W)
        
        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X)
        
        ttk.Button(button_frame, text="Save", command=self.save_credentials).pack(side=tk.RIGHT, padx=(5, 0))
        ttk.Button(button_frame, text="Test Connection", command=self.test_connection).pack(side=tk.RIGHT, padx=5)
        ttk.Button(button_frame, text="Clear All", command=self.clear_credentials).pack(side=tk.LEFT)
        ttk.Button(button_frame, text="Cancel", command=self.dialog.destroy).pack(side=tk.RIGHT)
    
    def save_credentials(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get()
        
        if not username or not password:
            messagebox.showerror("Error", "Please enter both email and password")
            return
        
        self.app.username = username
        self.app.password = password
        self.app.save_credentials()
        self.app.show_main_interface()
        messagebox.showinfo("Success", "Credentials saved successfully!")
        self.dialog.destroy()
    
    def test_connection(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get()
        
        if not username or not password:
            messagebox.showerror("Error", "Please enter both email and password")
            return
        
        def test():
            try:
                # Test IMAP connection
                with imaplib.IMAP4_SSL("imap.gmail.com") as mail:
                    mail.login(username, password)
                    mail.select("inbox")
                
                messagebox.showinfo("Success", "Connection test successful!")
            except Exception as e:
                messagebox.showerror("Connection Failed", f"Failed to connect: {e}")
        
        threading.Thread(target=test, daemon=True).start()
    
    def clear_credentials(self):
        if messagebox.askyesno("Confirm", "Clear all saved credentials?"):
            self.app.username = None
            self.app.password = None
            if os.path.exists(self.app.config_file):
                os.remove(self.app.config_file)
            messagebox.showinfo("Success", "Credentials cleared!")
            self.dialog.destroy()


def main():
    root = tk.Tk()
    app = GmailGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
