import os
import argparse
from dotenv import load_dotenv
from email_processor import EmailProcessor

def main():
    parser = argparse.ArgumentParser(description='Gmail Cleaner AI')
    parser.add_argument('--dry-run', action='store_true',
                      help='Run in dry-run mode (no actual deletions)')
    parser.add_argument('--batch-size', type=int, default=100,
                      help='Number of emails to process in each batch')
    args = parser.parse_args()

    # Load environment variables
    load_dotenv()

    # Validate environment
    required_vars = ['GMAIL_USER', 'MAX_UNREAD_AGE_DAYS']
    missing_vars = [var for var in required_vars if not os.getenv(var)]
    if missing_vars:
        print(f"Error: Missing required environment variables: {', '.join(missing_vars)}")
        print("Please check your .env file")
        return

    try:
        processor = EmailProcessor(dry_run=args.dry_run)
        processor.process_inbox(batch_size=args.batch_size)
    except Exception as e:
        print(f"Error: {str(e)}")
        return

if __name__ == "__main__":
    main() 