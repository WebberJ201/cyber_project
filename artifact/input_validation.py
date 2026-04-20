def validate_email_input(email):
    # Reject empty input
    if not email or len(email.strip()) == 0:
        return False
    
    # Block script injection attempts
    if "<script>" in email.lower():
        return False
    
    # Block extremely large inputs
    if len(email) > 10000:
        return False
    
    return True
