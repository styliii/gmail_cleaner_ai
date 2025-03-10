# Gmail Cleaner

![image](https://github.com/user-attachments/assets/a93c12c0-497b-4078-a8ba-bd2a262b5ddf)


An intelligent email management tool that helps organize your Gmail inbox by automatically:

- Identifying and archiving receipts
- Detecting and removing marketing emails
- Managing old unread emails
- Handling unsubscribe requests

## Features

- **Receipt Detection**: Automatically identifies receipts and order confirmations using pattern matching and moves them to a dedicated label
- **Marketing Email Management**: Identifies marketing emails and handles unsubscription when possible
- **Smart Classification**: Uses rule-based classification to identify important emails and prevent accidental deletion
- **Dry Run Mode**: Test the tool without making actual changes to your inbox

## Setup

1. Clone the repository:

```bash
git clone https://github.com/yourusername/GmailCleaner.git
cd GmailCleaner
```

2. Create and activate a virtual environment:

```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:

```bash
pip install -r requirements.txt
```

4. Create a `.env` file with your configuration:

```
GMAIL_USER=your.email@gmail.com
IMPORTANT_DOMAINS=domain1.com,domain2.com
MAX_UNREAD_AGE_DAYS=30
```

5. Set up Gmail API credentials:
   - Go to [Google Cloud Console](https://console.cloud.google.com)
   - Create a new project
   - Enable the Gmail API
   - Create OAuth 2.0 credentials
   - Download the credentials and save as `credentials.json` in the project directory

## Usage

Run in dry-run mode (no actual changes):

```bash
python main.py --dry-run
```

Run for real (will make actual changes to your inbox):

```bash
python main.py
```

## Configuration

The tool can be configured through environment variables in the `.env` file:

- `GMAIL_USER`: Your Gmail address
- `IMPORTANT_DOMAINS`: Comma-separated list of domains to never delete
- `MAX_UNREAD_AGE_DAYS`: Number of days after which unread emails are considered old

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
