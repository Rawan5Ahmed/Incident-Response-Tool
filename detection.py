def detect_events(log_file):
    """
    Detects suspicious events from a log file.
    Returns a list of tuples: (event_type, log_line)
    """
    events = []

    with open(log_file, "r") as f:
        for line in f:
            line_lower = line.lower()  # case-insensitive
            # Authentication events
            if "failed_login" in line_lower:
                events.append(("FAILED_LOGIN", line))
            elif "success_login" in line_lower:
                events.append(("SUCCESS_LOGIN", line))
            elif "brute_force_attempt" in line_lower:
                events.append(("BRUTE_FORCE_ATTEMPT", line))

            # User management
            elif "new_user" in line_lower:
                events.append(("NEW_USER", line))
            elif "user_removed" in line_lower:
                events.append(("USER_REMOVED", line))
            elif "user_added_to_admin_group" in line_lower:
                events.append(("PRIVILEGE_ESCALATION", line))

            # Process events
            elif "suspicious_process" in line_lower:
                events.append(("SUSPICIOUS_PROCESS", line))
            elif "unusual_process" in line_lower:
                events.append(("UNUSUAL_PROCESS", line))

            # Network events
            elif "failed_connection" in line_lower:
                events.append(("FAILED_CONNECTION", line))
            elif "malicious_ip" in line_lower:
                events.append(("MALICIOUS_IP", line))

            # File events
            elif "malicious_file" in line_lower:
                events.append(("MALICIOUS_FILE", line))
            elif "file_deletion" in line_lower:
                events.append(("FILE_DELETION", line))

    return events
