import os
from datetime import datetime, timezone
from dotenv import load_dotenv
import re

load_dotenv()

class EmailClassifier:
    def __init__(self):
        self.important_domains = set(os.getenv('IMPORTANT_DOMAINS', '').split(','))
        self.max_unread_age_days = int(os.getenv('MAX_UNREAD_AGE_DAYS', '30'))
        self.known_contacts = set()  # Will be populated from contacts API
        self.replied_threads = set()  # Will be populated from email analysis

    def is_marketing_email(self, headers):
        """Detect if an email is a marketing/promotional email."""
        # Check common marketing email indicators in headers
        for header in headers:
            if header['name'].lower() == 'list-unsubscribe':
                return True
            if header['name'].lower() == 'x-mailer':
                if any(term in header['value'].lower() for term in ['mailchimp', 'sendgrid', 'constant contact']):
                    return True
        return False

    def is_important_sender(self, from_email):
        """Check if the sender is considered important."""
        email = self._extract_email(from_email)
        domain = email.split('@')[-1] if email else ''
        
        return any([
            email in self.known_contacts,
            domain in self.important_domains,
            self._is_personal_email(email)
        ])

    def is_important_thread(self, thread_id):
        """Check if the email thread is important."""
        return thread_id in self.replied_threads

    def is_too_old(self, timestamp, is_read):
        """Check if an unread email is too old."""
        if is_read:
            return False
            
        email_date = datetime.fromtimestamp(int(timestamp) / 1000, timezone.utc)
        age_days = (datetime.now(timezone.utc) - email_date).days
        return age_days > self.max_unread_age_days

    def _extract_email(self, from_string):
        """Extract email address from a from string."""
        match = re.search(r'<(.+?)>', from_string)
        if match:
            return match.group(1).lower()
        return from_string.lower()

    def _is_personal_email(self, email):
        """Heuristic to detect if an email looks like a personal address."""
        if not email:
            return False
            
        # Exclude common marketing patterns
        marketing_patterns = [
            'noreply', 'no-reply', 'donotreply', 'newsletter', 'marketing',
            'info@', 'support@', 'sales@', 'contact@'
        ]
        return not any(pattern in email.lower() for pattern in marketing_patterns)

    def update_known_contacts(self, contacts):
        """Update the set of known contacts."""
        self.known_contacts.update(contacts)

    def update_replied_threads(self, threads):
        """Update the set of threads that have been replied to."""
        self.replied_threads.update(threads) 