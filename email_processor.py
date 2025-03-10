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
        
        # API usage tracking
        self.total_tokens_used = 0
        self.total_api_calls = 0
        self.total_api_cost = 0
        self.input_tokens = 0
        self.output_tokens = 0
        
        # Initialize OpenAI client
        openai_api_key = os.getenv('OPENAI_API_KEY')
        if not openai_api_key:
            raise ValueError("OPENAI_API_KEY not found in environment variables")
        self.client = openai.OpenAI(api_key=openai_api_key)
        
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
        """Process emails in the inbox from the past 3 days."""
        print("\nStarting email processing...")
        
        # Calculate date range for past 3 days
        now = datetime.now(timezone.utc)
        older_than = int((now - timedelta(days=0)).timestamp())  # Now
        newer_than = int((now - timedelta(days=3)).timestamp())  # 3 days ago
        
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

    def _is_past_date(self, text: str, message_date: str) -> bool:
        """Check if a date mentioned in the text is in the past."""
        try:
            # Convert message date to datetime
            message_dt = datetime.strptime(message_date, '%Y-%m-%d %H:%M:%S')
            
            # Common date patterns
            date_patterns = [
                r'(?:jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|jun(?:e)?|jul(?:y)?|aug(?:ust)?|sep(?:tember)?|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?)\s+\d{1,2}(?:st|nd|rd|th)?(?:\s*,?\s*\d{4})?',
                r'\d{1,2}/\d{1,2}(?:/\d{2,4})?',
                r'\d{4}-\d{2}-\d{2}',
                r'(?:monday|tuesday|wednesday|thursday|friday|saturday|sunday),?\s+(?:jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|jun(?:e)?|jul(?:y)?|aug(?:ust)?|sep(?:tember)?|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?)\s+\d{1,2}(?:st|nd|rd|th)?(?:\s*,?\s*\d{4})?'
            ]
            
            # Time patterns
            time_patterns = [
                r'\d{1,2}:\d{2}\s*(?:am|pm)?',
                r'\d{1,2}\s*(?:am|pm)'
            ]
            
            # Current time for comparison
            now = datetime.now()
            
            # Look for dates in the text
            for pattern in date_patterns:
                matches = re.finditer(pattern, text.lower())
                for match in matches:
                    try:
                        # Parse the date string
                        date_str = match.group()
                        # Try different date formats
                        for fmt in ['%B %d, %Y', '%B %d %Y', '%b %d, %Y', '%b %d %Y', 
                                  '%m/%d/%Y', '%m/%d/%y', '%Y-%m-%d']:
                            try:
                                date = datetime.strptime(date_str, fmt)
                                if date < now:
                                    return True
                            except ValueError:
                                continue
                    except:
                        continue
            
            return False
        except:
            return False

    def _analyze_email_content(self, subject: str, body: str, sender: str) -> Dict[str, bool]:
        """
        Analyze email content using OpenAI's GPT model.
        Returns a dictionary of classifications.
        """
        try:
            # Prepare the message for GPT
            system_prompt = """You are an email classifier that analyzes emails and determines their categories.
            Classify the email into these categories:
            1. is_receipt: Is this a receipt, order confirmation, financial transaction, or DoorDash order?
            2. is_marketing: Is this a marketing or promotional email, or does it have an unsubscribe option?
            3. is_important: Is this an important email that needs attention?
            4. should_delete: Should this email be deleted?
            5. is_past_appointment: Is this an appointment reminder for a date that has already passed?
            
            Respond with a JSON object containing boolean values for each category.
            Consider:
            - Receipts include:
              * Order confirmations and payment notifications
              * Financial transactions
              * DoorDash orders and delivery confirmations
              * Any purchase or payment related email
            - Marketing emails include:
              * ANY email that has an unsubscribe link or option
              * Promotional content and advertisements
              * Newsletters and updates
              * Sales and special offers
            - Important emails include:
              * Security alerts and account notifications
              * Personal communications
              * Work-related content
              * Time-sensitive information
              * Medical or health-related communications
              * Direct communications from teachers/schools about current students
            - Past appointments include:
              * Calendar notifications for past dates
              * Appointment reminders for dates that have passed
              * Meeting confirmations for past events
            - Emails should be deleted if:
              * They have an unsubscribe option
              * They are marketing/promotional
              * They are not important
            
            Pay special attention to security-related emails (password changes, security alerts, account notifications) - 
            these should ALWAYS be marked as important regardless of the sender."""

            user_prompt = f"""Subject: {subject}
            From: {sender}
            Content: {body[:1000]}  # Limit content length for token usage
            
            Classify this email based on the given categories."""

            # Make API call
            response = self.client.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ]
            )

            # Update usage tracking
            usage = response.usage
            self.input_tokens += usage.prompt_tokens
            self.output_tokens += usage.completion_tokens
            self.total_tokens_used += usage.total_tokens
            self.total_api_calls += 1
            
            # Calculate cost (based on current GPT-3.5-turbo pricing)
            input_cost = (usage.prompt_tokens / 1000) * 0.0005
            output_cost = (usage.completion_tokens / 1000) * 0.0015
            self.total_api_cost += input_cost + output_cost

            # Parse the response
            try:
                result = json.loads(response.choices[0].message.content)
                # Ensure all required keys are present
                required_keys = ['is_receipt', 'is_marketing', 'is_important', 'should_delete', 'is_past_appointment']
                for key in required_keys:
                    if key not in result:
                        result[key] = False
                return result
            except json.JSONDecodeError:
                print(f"Warning: Could not parse AI response for email: {subject}")
                return {
                    'is_receipt': False,
                    'is_marketing': False,
                    'is_important': False,
                    'should_delete': False,
                    'is_past_appointment': False
                }

        except Exception as e:
            print(f"Warning: AI analysis failed for email: {subject}. Error: {str(e)}")
            # Fallback to rule-based classification
            return self._rule_based_classification(subject, body, sender)

    def _rule_based_classification(self, subject: str, body: str, sender: str) -> Dict[str, bool]:
        """Fallback rule-based classification when AI analysis fails."""
        # Initialize result
        result = {
            'is_receipt': False,
            'is_marketing': False,
            'is_important': False,
            'should_delete': False,
            'is_past_appointment': False
        }
        
        # Convert to lowercase for case-insensitive matching
        subject_lower = subject.lower()
        sender_lower = sender.lower()
        body_lower = body.lower()[:1000]
        
        # Receipt patterns
        receipt_keywords = [
            'receipt', 'order confirmation', 'invoice', 'payment confirmation',
            'your order', 'transaction', 'purchase', 'payment received',
            'doordash order', 'your doordash order', 'order from doordash',
            'delivery confirmation', 'order #', 'payment processed',
            'your receipt from apple', 'receipt from apple', 'subscription is expiring',
            'order id:', 'subscription expiring', 'subscription renewal'
        ]
        dollar_pattern = r'\$\d{1,3}(?:,\d{3})*(?:\.\d{2})?'
        has_dollar_amount = bool(re.search(dollar_pattern, body) or re.search(dollar_pattern, subject))
        
        # Check for DoorDash specifically
        is_doordash = 'doordash' in sender_lower or 'doordash' in subject_lower
        
        # Check for Apple specifically
        is_apple = 'apple' in sender_lower and ('receipt' in subject_lower or 'subscription' in subject_lower)
        
        result['is_receipt'] = has_dollar_amount or any(keyword in subject_lower or keyword in body_lower 
                                                       for keyword in receipt_keywords) or is_doordash or is_apple
        
        # Check for unsubscribe link/text
        unsubscribe_patterns = [
            'unsubscribe', 'opt-out', 'opt out', 'email preferences',
            'email settings', 'manage subscriptions', 'manage your preferences',
            'update your preferences', 'subscription center'
        ]
        has_unsubscribe = any(pattern in body_lower for pattern in unsubscribe_patterns)
        
        # Marketing patterns
        marketing_keywords = [
            'newsletter', 'subscription', 'marketing',
            'special offer', 'discount', 'sale', 'promotion', 'deal',
            'exclusive', 'limited time', 'early bird', 'sign up now',
            'register today', 'join us', 'don\'t miss'
        ]
        result['is_marketing'] = has_unsubscribe or any(keyword in subject_lower or keyword in body_lower 
                                                   for keyword in marketing_keywords)
        
        # Security and important patterns
        security_keywords = [
            'security', 'password', 'login', 'account', 'verify',
            'authentication', 'protect', 'suspicious', 'unauthorized',
            'alert', 'warning', 'important notice'
        ]
        
        # Check if email is security related
        is_security_related = any(keyword in subject_lower or keyword in body_lower 
                                for keyword in security_keywords)
        
        # Important patterns
        important_domains = os.getenv('IMPORTANT_DOMAINS', '').split(',')
        sender_domain = sender_lower.split('@')[-1] if '@' in sender_lower else ''
        
        result['is_important'] = (
            is_security_related or
            sender_domain in important_domains or
            sender in self.classifier.known_contacts
        )
        
        # Deletion criteria
        # Delete if it has unsubscribe option or is marketing, unless it's important
        result['should_delete'] = (has_unsubscribe or result['is_marketing']) and not result['is_important']
        
        # Appointment patterns
        appointment_keywords = [
            'appointment', 'reminder', 'meeting', 'scheduled', 'calendar',
            'appointment confirmation', 'your appointment', 'upcoming appointment',
            'meeting reminder', 'event reminder', 'reservation'
        ]
        
        # Check if it's an appointment email
        is_appointment = any(keyword in subject_lower or keyword in body_lower 
                            for keyword in appointment_keywords)
        
        if is_appointment:
            result['is_past_appointment'] = self._is_past_date(subject + ' ' + body_lower, 
                                                              datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        
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

    def _get_list_identifier(self, headers) -> str:
        """Extract a unique identifier for the mailing list from headers."""
        # Try List-ID header first
        list_id = next((h['value'] for h in headers if h['name'] == 'List-ID'), None)
        if list_id:
            return list_id

        # Try List-Unsubscribe header
        unsubscribe = next((h['value'] for h in headers if h['name'] == 'List-Unsubscribe'), None)
        if unsubscribe:
            return unsubscribe

        # Fallback to From header
        from_header = next((h['value'] for h in headers if h['name'] == 'From'), '')
        return from_header

    def _bulk_delete_from_list(self, list_identifier: str):
        """Delete all emails from the same mailing list."""
        if self.dry_run:
            print(f"Would delete all emails from: {list_identifier}")
            return

        try:
            # Construct search query based on list identifier
            if '@' in list_identifier:
                # If it's an email address, search by from:
                query = f'from:({list_identifier})'
            else:
                # Otherwise search in full text
                # Escape special characters in the list identifier
                safe_id = list_identifier.replace('"', '').replace('\'', '')
                query = f'"{safe_id}"'

            # Search for all emails from this list
            results = self.service.users().messages().list(
                userId='me',
                q=query
            ).execute()

            messages = results.get('messages', [])
            if messages:
                print(f"Found {len(messages)} additional emails from this mailing list")
                for message in messages:
                    self._delete_message(message['id'])
                    self.deleted_details.append({
                        'id': message['id'],
                        'subject': 'Bulk deleted from mailing list',
                        'sender': list_identifier,
                        'date': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    })

        except Exception as e:
            print(f"Error in bulk deletion: {str(e)}")

    def _process_message(self, message_id):
        """Process a single message using rule-based analysis."""
        message = self.service.users().messages().get(
            userId='me',
            id=message_id,
            format='metadata',
            metadataHeaders=['From', 'Subject', 'List-Unsubscribe', 'List-ID']
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

        # Handle past appointments
        if analysis.get('is_past_appointment', False):
            self._archive_message(message_id)
            return

        # Handle important emails
        if analysis['is_important']:
            self.important_details.append(email_details)
            return

        # Handle marketing emails
        if analysis['is_marketing']:
            self.marketing_deletions += 1
            self.marketing_details.append(email_details)
            
            # Get list identifier before unsubscribing
            list_identifier = self._get_list_identifier(headers)
            
            # Try to unsubscribe
            self._handle_unsubscribe(message_id, headers)
            
            # Bulk delete all emails from this list
            if list_identifier:
                self._bulk_delete_from_list(list_identifier)
            
            return

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

    def _archive_message(self, message_id):
        """Archive a message by removing it from the inbox."""
        if self.dry_run:
            print(f"Would archive message: {message_id}")
        else:
            try:
                self.service.users().messages().modify(
                    userId='me',
                    id=message_id,
                    body={'removeLabelIds': ['INBOX']}
                ).execute()
            except Exception as e:
                print(f"Error archiving message {message_id}: {str(e)}")

    def _print_summary(self):
        """Print summary of email processing including API usage statistics."""
        print("\nProcessing Summary:")
        print(f"Total messages processed: {self.processed_count}")
        print(f"Messages deleted: {self.deleted_count}")
        
        print(f"\nReceipts found ({len(self.receipt_details)}):")
        for detail in self.receipt_details:
            print(f"  - {detail}")
            
        print(f"\nMarketing emails ({len(self.marketing_details)}):")
        for detail in self.marketing_details:
            print(f"  - {detail}")
            
        print(f"\nImportant emails preserved ({len(self.important_details)}):")
        for detail in self.important_details:
            print(f"  - {detail}")
            
        print(f"\nEmails to be deleted ({len(self.deleted_details)}):")
        for detail in self.deleted_details:
            print(f"  - {detail}")
        
        print("\nDeletion reasons:")
        print(f"  - Marketing emails: {self.marketing_deletions}")
        print(f"  - Old unread emails: {self.old_unread_deletions}")
        print(f"Receipts archived: {self.receipts_archived}")
        print(f"Unsubscribe attempts: {self.unsubscribed_count}")
        
        print("\nAPI Usage Statistics:")
        print(f"Total API calls: {self.total_api_calls}")
        print(f"Total tokens used: {self.total_tokens_used}")
        print(f"  - Input tokens: {self.input_tokens}")
        print(f"  - Output tokens: {self.output_tokens}")
        print(f"Estimated cost: ${self.total_api_cost:.4f}")
        
        if self.dry_run:
            print("\nThis was a dry run. No emails were actually deleted, archived, or unsubscribed.") 