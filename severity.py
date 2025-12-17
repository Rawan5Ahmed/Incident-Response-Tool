def get_severity(event_type, rules):
    """
    Return severity level of the event based on rules.json
    """
    return rules.get(event_type, "Low")
