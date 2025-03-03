import base64
import json
import os
import time
import re
from datetime import datetime, timezone, timedelta
from tqdm import tqdm
from email_classifier import EmailClassifier
from gmail_auth import GmailAuth
import openai
from typing import Dict, List, Tuple

class EmailProcessor:
    def __init__(self, dry_run=True):
        print("Initializing Email Processor...")
        self.auth = GmailAuth()
        print("Getting Gmail service...")
        self.service = self.auth.get_service()
        self.classifier = EmailClassifier()
        self.dry_run = dry_run
        self.processed_count = 0
        self.deleted_count = 0
        self.unsubscribed_count = 0
        self.receipts_archived = 0
        # Add counters for deletion reasons
        self.marketing_deletions = 0
        self.old_unread_deletions = 0
        
        # Add lists to store details about processed emails
        self.receipt_details = []
        self.marketing_details = []
        self.deleted_details = []
        self.important_details = []
        
        # Initialize OpenAI
        openai.api_key = os.getenv('OPENAI_API_KEY')
        if not openai.api_key:
            print("Warning: OPENAI_API_KEY not found in environment variables")
        
        # Create Receipt label if it doesn't exist
        self._ensure_receipt_label()
        print("Email Processor initialized")

    def _ensure_receipt_label(self):
        """Ensure the Receipt label exists, create if it doesn't."""
        try:
            results = self.service.users().labels().list(userId='me').execute()
            labels = results.get('labels', [])
            
            # Check if Receipt label exists
            receipt_label = next((label for label in labels if label['name'] == 'Receipt'), None)
            
            if not receipt_label:
                if not self.dry_run:
                    label_object = {
                        'name': 'Receipt',
                        'labelListVisibility': 'labelShow',
                        'messageListVisibility': 'show'
                    }
                    receipt_label = self.service.users().labels().create(
                        userId='me',
                        body=label_object
                    ).execute()
                self.receipt_label_id = receipt_label['id'] if receipt_label else None
            else:
                self.receipt_label_id = receipt_label['id']
                
        except Exception as e:
            print(f"Warning: Could not create Receipt label: {str(e)}")
            self.receipt_label_id = None

    def _is_receipt(self, headers, snippet, message_id):
        """Check if an email is a receipt or order confirmation."""
        # Dollar amount pattern: matches $X, $X.XX, $X,XXX.XX formats
        dollar_pattern = r'\$\d{1,3}(?:,\d{3})*(?:\.\d{2})?'
        
        # Check for dollar amounts in the snippet
        if re.search(dollar_pattern, snippet):
            return True
        
        # If no dollar amount in snippet, check the full message content
        try:
            full_message = self.service.users().messages().get(
                userId='me',
                id=message_id,
                format='full'
            ).execute()
            
            # Get message body
            if 'data' in full_message['payload']['body']:
                message_data = base64.urlsafe_b64decode(
                    full_message['payload']['body']['data'].encode('UTF-8')
                ).decode('utf-8')
            else:
                # Handle multipart messages
                parts = full_message['payload'].get('parts', [])
                message_data = ''
                for part in parts:
                    if part.get('mimeType') == 'text/plain' and 'data' in part.get('body', {}):
                        part_data = base64.urlsafe_b64decode(
                            part['body']['data'].encode('UTF-8')
                        ).decode('utf-8')
                        message_data += part_data
            
            # Check for dollar amounts in the full message
            if re.search(dollar_pattern, message_data):
                return True
                
        except Exception as e:
            print(f"Warning: Could not check full message content: {str(e)}")
        
        return False

    def process_inbox(self, batch_size=100):
        """Process emails in the inbox within 30-60 days old range."""
        print("\nStarting email processing...")
        
        # Calculate date range
        now = datetime.now(timezone.utc)
        older_than = int((now - timedelta(days=30)).timestamp())
        newer_than = int((now - timedelta(days=31)).timestamp())
        
        print(f"Searching for emails between {datetime.fromtimestamp(newer_than)} and {datetime.fromtimestamp(older_than)}")
        
        # First, build our knowledge base
        self._build_knowledge_base()
        
        try:
            next_page_token = None
            while True:
                # Add date range to query
                query = f'after:{newer_than} before:{older_than}'
                print(f"\nFetching messages with query: {query}")
                
                results = self.service.users().messages().list(
                    userId='me',
                    maxResults=batch_size,
                    pageToken=next_page_token,
                    q=query
                ).execute()

                messages = results.get('messages', [])
                print(f"Found {len(messages)} messages in this batch")
                
                if not messages:
                    print("No messages found in this range")
                    break

                self._process_batch(messages)
                
                next_page_token = results.get('nextPageToken')
                if not next_page_token:
                    print("No more messages to process")
                    break

        except Exception as e:
            print(f"Error processing inbox: {str(e)}")
            raise

        self._print_summary()

    def _build_knowledge_base(self):
        """Build knowledge base of contacts and replied threads."""
        print("\nBuilding knowledge base...")
        
        # Get contacts
        contacts = set()
        try:
            print("Fetching contacts...")
            # This requires additional setup with People API
            people_service = self.service
            connections = people_service.people().connections().list(
                resourceName='people/me',
                personFields='emailAddresses'
            ).execute()
            
            for person in connections.get('connections', []):
                for email in person.get('emailAddresses', []):
                    contacts.add(email.get('value').lower())
            print(f"Found {len(contacts)} contacts")
        except Exception as e:
            print(f"Warning: Could not fetch contacts: {str(e)}")

        self.classifier.update_known_contacts(contacts)

        # Get threads you've replied to
        replied_threads = set()
        try:
            print("\nFetching replied threads...")
            results = self.service.users().messages().list(
                userId='me',
                q='from:me'
            ).execute()
            
            messages = results.get('messages', [])
            for message in messages:
                replied_threads.add(message['threadId'])
            print(f"Found {len(replied_threads)} replied threads")
        except Exception as e:
            print(f"Warning: Could not fetch replied threads: {str(e)}")

        self.classifier.update_replied_threads(replied_threads)
        print("Knowledge base built successfully")

    def _process_batch(self, messages):
        """Process a batch of messages."""
        for message in tqdm(messages, desc="Processing emails"):
            try:
                self._process_message(message['id'])
                time.sleep(0.1)  # Rate limiting
            except Exception as e:
                print(f"Error processing message {message['id']}: {str(e)}")

    def _analyze_email_content(self, subject: str, body: str, sender: str) -> Dict[str, bool]:
        """
        Analyze email content using rule-based classification.
        Returns a dictionary of classifications.
        """
        # Initialize result
        result = {
            'is_receipt': False,
            'is_marketing': False,
            'is_important': False,
            'should_delete': False
        }
        
        # Convert to lowercase for case-insensitive matching
        subject_lower = subject.lower()
        sender_lower = sender.lower()
        body_lower = body.lower()[:1000]  # Limit content length for performance
        
        # Receipt patterns
        receipt_keywords = [
            'receipt', 'order confirmation', 'invoice', 'payment confirmation',
            'your order', 'transaction', 'purchase', 'payment received'
        ]
        # Check for dollar amounts
        dollar_pattern = r'\$\d{1,3}(?:,\d{3})*(?:\.\d{2})?'
        has_dollar_amount = bool(re.search(dollar_pattern, body) or re.search(dollar_pattern, subject))
        
        result['is_receipt'] = has_dollar_amount or any(keyword in subject_lower or keyword in body_lower 
                                                       for keyword in receipt_keywords)
        
        # Marketing patterns
        marketing_keywords = [
            'unsubscribe', 'newsletter', 'subscription', 'marketing',
            'special offer', 'discount', 'sale', 'promotion', 'deal',
            'limited time', 'exclusive offer', 'off selected', '% off'
        ]
        marketing_patterns = [
            r'view.*online',
            r'click here',
            r'\d+% off',
            r'save up to',
            r'limited time'
        ]
        
        result['is_marketing'] = (
            any(keyword in subject_lower or keyword in body_lower for keyword in marketing_keywords) or
            any(re.search(pattern, body_lower) for pattern in marketing_patterns)
        )
        
        # Important email patterns
        important_keywords = [
            'urgent', 'important', 'action required', 'deadline',
            'account', 'security', 'password', 'payment due',
            'meeting', 'interview', 'appointment'
        ]
        # Check if sender is from important domains
        important_domains = os.getenv('IMPORTANT_DOMAINS', '').split(',')
        sender_domain = sender_lower.split('@')[-1] if '@' in sender_lower else ''
        
        result['is_important'] = (
            any(keyword in subject_lower for keyword in important_keywords) or
            any(domain in sender_domain for domain in important_domains) or
            self.classifier.is_important_sender(sender)
        )
        
        # Determine if email should be deleted
        result['should_delete'] = (
            result['is_marketing'] and not result['is_important'] and not result['is_receipt']
        )
        
        return result

    def _get_email_content(self, message_id: str) -> Tuple[str, str, str]:
        """Get the subject, body, and sender of an email."""
        try:
            message = self.service.users().messages().get(
                userId='me',
                id=message_id,
                format='full'
            ).execute()

            # Get headers
            headers = message['payload']['headers']
            subject = next((h['value'] for h in headers if h['name'] == 'Subject'), '')
            sender = next((h['value'] for h in headers if h['name'] == 'From'), '')

            # Get body
            if 'data' in message['payload']['body']:
                body = base64.urlsafe_b64decode(
                    message['payload']['body']['data'].encode('UTF-8')
                ).decode('utf-8')
            else:
                # Handle multipart messages
                parts = message['payload'].get('parts', [])
                body = ''
                for part in parts:
                    if part.get('mimeType') == 'text/plain' and 'data' in part.get('body', {}):
                        part_data = base64.urlsafe_b64decode(
                            part['body']['data'].encode('UTF-8')
                        ).decode('utf-8')
                        body += part_data

            return subject, body, sender

        except Exception as e:
            print(f"Warning: Could not get email content: {str(e)}")
            return '', '', ''

    def _process_message(self, message_id):
        """Process a single message using rule-based analysis."""
        message = self.service.users().messages().get(
            userId='me',
            id=message_id,
            format='metadata',
            metadataHeaders=['From', 'Subject', 'List-Unsubscribe']
        ).execute()

        headers = message['payload']['headers']
        from_header = next((h for h in headers if h['name'] == 'From'), None)
        subject_header = next((h for h in headers if h['name'] == 'Subject'), None)
        
        if not from_header or not subject_header:
            return

        # Get full email content for analysis
        subject = subject_header['value']
        sender = from_header['value']
        _, body, _ = self._get_email_content(message_id)
        
        # Store email details
        email_details = {
            'id': message_id,
            'subject': subject,
            'sender': sender,
            'date': datetime.fromtimestamp(int(message['internalDate'])/1000).strftime('%Y-%m-%d %H:%M:%S')
        }
        
        # Perform analysis
        analysis = self._analyze_email_content(subject, body, sender)
        
        # Handle receipts
        if analysis['is_receipt']:
            self._handle_receipt(message_id)
            self.receipt_details.append(email_details)
            return

        # Handle important emails
        if analysis['is_important']:
            self.important_details.append(email_details)
            return

        # Handle marketing emails
        if analysis['is_marketing']:
            self.marketing_deletions += 1
            self.marketing_details.append(email_details)
            self._handle_unsubscribe(message_id, headers)

        # Handle emails that should be deleted
        if analysis['should_delete']:
            self._delete_message(message_id)
            self.deleted_details.append(email_details)
            return

        # Check for old unread emails as a fallback
        if self.classifier.is_too_old(message['internalDate'], 
                                    'UNREAD' in message['labelIds']):
            self.old_unread_deletions += 1
            self._delete_message(message_id)
            self.deleted_details.append(email_details)

    def _handle_receipt(self, message_id):
        """Handle receipt emails by labeling and archiving them."""
        if self.dry_run:
            print(f"Would label and archive receipt: {message_id}")
            self.receipts_archived += 1
            return

        try:
            # Add Receipt label
            if self.receipt_label_id:
                self.service.users().messages().modify(
                    userId='me',
                    id=message_id,
                    body={'addLabelIds': [self.receipt_label_id], 'removeLabelIds': ['INBOX']}
                ).execute()
                self.receipts_archived += 1
        except Exception as e:
            print(f"Error handling receipt {message_id}: {str(e)}")

    def _handle_unsubscribe(self, message_id, headers):
        """Handle unsubscription if possible."""
        unsubscribe_header = next(
            (h for h in headers if h['name'] == 'List-Unsubscribe'),
            None
        )

        if not unsubscribe_header:
            return

        try:
            # Extract unsubscribe URLs and mailto links
            unsubscribe_value = unsubscribe_header['value']
            
            # Handle multiple unsubscribe options
            if not self.dry_run:
                if 'mailto:' in unsubscribe_value:
                    mailto = re.search(r'mailto:([^>,]*)', unsubscribe_value).group(1)
                    self._send_unsubscribe_email(mailto)
                    print(f"Sent unsubscribe email to: {mailto}")
                elif 'http' in unsubscribe_value:
                    # Extract HTTP URL
                    http_url = re.search(r'https?://[^>,\s]+', unsubscribe_value).group(0)
                    print(f"HTTP unsubscribe URL (please visit manually): {http_url}")
            else:
                print(f"Would attempt to unsubscribe using: {unsubscribe_value}")
            
            self.unsubscribed_count += 1
        except Exception as e:
            print(f"Failed to unsubscribe: {str(e)}")

    def _send_unsubscribe_email(self, mailto):
        """Send an unsubscribe email."""
        if self.dry_run:
            return

        try:
            message = {
                'raw': base64.urlsafe_b64encode(
                    f"To: {mailto}\nSubject: Unsubscribe\n\nPlease unsubscribe me."
                    .encode()
                ).decode()
            }
            self.service.users().messages().send(
                userId='me',
                body=message
            ).execute()
        except Exception as e:
            print(f"Failed to send unsubscribe email: {str(e)}")

    def _delete_message(self, message_id):
        """Delete or trash a message."""
        if self.dry_run:
            print(f"Would delete message: {message_id}")
        else:
            self.service.users().messages().trash(
                userId='me',
                id=message_id
            ).execute()
        self.deleted_count += 1

    def _print_summary(self):
        """Print a summary of the processing results with detailed information."""
        print("\nProcessing Summary:")
        print(f"Total messages processed: {self.processed_count}")
        print(f"Messages deleted: {self.deleted_count}")
        
        print("\nReceipts found ({len(self.receipt_details)}):")
        for receipt in self.receipt_details:
            print(f"  - [{receipt['date']}] {receipt['subject']} (From: {receipt['sender']})")
            
        print("\nMarketing emails ({len(self.marketing_details)}):")
        for marketing in self.marketing_details:
            print(f"  - [{marketing['date']}] {marketing['subject']} (From: {marketing['sender']})")
            
        print("\nImportant emails preserved ({len(self.important_details)}):")
        for important in self.important_details:
            print(f"  - [{important['date']}] {important['subject']} (From: {important['sender']})")
            
        print("\nEmails to be deleted ({len(self.deleted_details)}):")
        for deleted in self.deleted_details:
            print(f"  - [{deleted['date']}] {deleted['subject']} (From: {deleted['sender']})")
            
        print("\nDeletion reasons:")
        print(f"  - Marketing emails: {self.marketing_deletions}")
        print(f"  - Old unread emails: {self.old_unread_deletions}")
        print(f"Receipts archived: {self.receipts_archived}")
        print(f"Unsubscribe attempts: {self.unsubscribed_count}")
        
        if self.dry_run:
            print("\nThis was a dry run. No emails were actually deleted, archived, or unsubscribed.") 