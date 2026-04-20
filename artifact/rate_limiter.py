import time

requests = []

def allow_request():
    current_time = time.time()

    # keep only last 60 seconds
    global requests
    requests = [r for r in requests if current_time - r < 60]

    if len(requests) > 10:
        return False  # too many requests (prevents probing)

    requests.append(current_time)
    return True
