import re

# Sample list of suspicious phone numbers
suspicious_senders = ["+1234567890", "+0987654321"]

# Sample list of phishing-related keywords
phishing_keywords = ["win", "claim", "prize", "urgent", "transfer"]

# Function to check if a message contains a URL
def contains_url(message):
    url_pattern = re.compile(
        r"(https?://(?:www\.|(?!www))[a-zA-Z0-9][a-zA-Z0-9-]+\.[^\s]{2,}|www\.[a-zA-Z0-9][a-zA-Z0-9-]+\.[^\s]{2,}|https?://[^\s]+|www\.[^\s]+)"
    )
    return bool(url_pattern.search(message))

# Function to check if the sender is suspicious
def is_suspicious_sender(sender):
    return sender in suspicious_senders

# Function to check if the message contains any currency symbols or phishing keywords
def contains_currency_or_keywords(message):
    # Check for currency symbols
    currency_symbols = ["$", "€", "£", "¥"]
    if any(symbol in message for symbol in currency_symbols):
        return True
    
    # Check for phishing keywords
    for keyword in phishing_keywords:
        if keyword in message.lower():
            return True
    
    return False

# Main function that applies the criteria one by one in order
def filter_message(message, sender):
    # Criteria rank: URL check -> Suspicious sender -> Currency/keywords
    # 1. Check for URLs first
    if contains_url(message):
        return "Flagged: URL detected"
    
    # 2. Check for suspicious sender
    if is_suspicious_sender(sender):
        return "Flagged: Suspicious sender detected"
    
    # 3. Check for currency symbols or phishing-related keywords
    if contains_currency_or_keywords(message):
        return "Flagged: Currency or phishing keywords detected"
    
    # If no criteria are matched, consider it safe
    return "Likely safe"

# Test the system with sample messages
test_messages = [
    ("You've won $1000! Claim your prize at http://scam.com", "+1234567890"),
    ("Hello, let's meet up tomorrow.", "+1987654321"),
    ("Urgent! Transfer €500 to the following account: http://phishingsite.com", "+11234567890"),
]

for message, sender in test_messages:
    print(f"Message: {message}\nSender: {sender}")
    result = filter_message(message, sender)
    print(f"Classification: {result}\n")
