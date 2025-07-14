import email
from unittest import mock

import pytest

from gmail_client import GmailClient


def make_message(from_addr='', subject=''):
    return email.message_from_string(f"From: {from_addr}\nSubject: {subject}\n\nBody")


def test_list_emails_basic():
    client = GmailClient()
    with mock.patch.object(GmailClient, '_select_folder') as mock_select, \
         mock.patch.object(GmailClient, '_search', return_value=[b'1', b'2']) as mock_search, \
         mock.patch.object(GmailClient, '_fetch_email') as mock_fetch:
        mock_fetch.side_effect = [make_message('Alice', 'Hello'), make_message('Bob', 'Hi')]
        emails = client.list_emails(folder='INBOX', criteria='ALL')
        assert emails == [
            {'uid': '1', 'from': 'Alice', 'subject': 'Hello'},
            {'uid': '2', 'from': 'Bob', 'subject': 'Hi'},
        ]
        mock_select.assert_called_once_with('INBOX')
        mock_search.assert_called_once_with('ALL')
        assert mock_fetch.call_count == 2


def test_list_emails_no_messages():
    client = GmailClient()
    with mock.patch.object(GmailClient, '_select_folder') as mock_select, \
         mock.patch.object(GmailClient, '_search', return_value=[]) as mock_search:
        emails = client.list_emails(folder='INBOX', criteria='ALL')
        assert emails == []
        mock_select.assert_called_once_with('INBOX')
        mock_search.assert_called_once_with('ALL')


def test_list_emails_missing_fields():
    client = GmailClient()
    with mock.patch.object(GmailClient, '_select_folder'), \
         mock.patch.object(GmailClient, '_search', return_value=[b'1']) , \
         mock.patch.object(GmailClient, '_fetch_email', return_value=make_message()):
        emails = client.list_emails()
        assert emails == [{'uid': '1', 'from': '', 'subject': ''}]

