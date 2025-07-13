# Python Gmail Connector

This repository contains a simple `GmailConnector` class that demonstrates
how to log in to Gmail using an application password via IMAP.

## Usage

1. Create a `credentials.json` file in the same directory with the following
   structure:

```json
{
    "email": "your_email@gmail.com",
    "app_password": "your_app_password"
}
```

2. Run the connector:

```bash
python3 gmail_connector.py
```

The script will attempt to connect to Gmail and print a message on success.
Remember to generate an app password in your Google account settings if you
have two-factor authentication enabled.

