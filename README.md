# Python Gmail Client

This repository demonstrates how to connect to Gmail using IMAP and SMTP with an application password.
It now includes a small Gmail client capable of reading and sending email and applying simple rules to automatically process messages.

## Credentials

Create a `credentials.json` file in the same directory with the following structure:

```json
{
    "email": "your_email@gmail.com",
    "app_password": "your_app_password"
}
```

Generate an app password in your Google account settings if you have two-factor authentication enabled.

## Usage

### Connecting

To test a basic connection run:

```bash
python3 gmail_connector.py
```

This will log in using the credentials and immediately log out.

### Gmail Client

`gmail_client.py` provides additional functionality:

- Reading messages from a folder.
- Sending email via SMTP.
- Applying rules defined in `rules.json` to automatically delete, move or label messages.

Create a `rules.json` file, for example:

```json
[
    {"pattern": "newsletter", "search_field": "subject", "action": "MOVE", "folder": "Newsletters"},
    {"pattern": "promo", "search_field": "body", "action": "DELETE"},
    {"pattern": "invoice", "search_field": "subject", "action": "MARK_IMPORTANT"}
]
```

Run the client with:

```bash
python3 gmail_client.py
```

The script will load your credentials, connect to Gmail, apply any rules, and then log out.
Sending email is demonstrated in the code and can be enabled by uncommenting the example line.
