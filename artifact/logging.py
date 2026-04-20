def log_event(event_type, message):
    with open("security_log.txt", "a") as file:
        file.write(f"{event_type}: {message}\n")
