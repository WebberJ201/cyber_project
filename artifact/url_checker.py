import re

def detect_suspicious_url(url):
    suspicious_patterns = [
        "paypa1",   # lookalike domain
        "secure-login",
        "verify-account",
        "update-info"
    ]

    for pattern in suspicious_patterns:
        if pattern in url.lower():
            return True

    return False
