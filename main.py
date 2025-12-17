import json
from detection import detect_events
from severity import get_severity
from storage import init_db, save_incident
from evidence import collect_evidence
from response import alert

LOG_FILE = "security.txt"

def main():
    print("Starting IR-ATS...")

    # Load rules
    with open("rules.json") as f:
        rules = json.load(f)

    # Initialize database
    init_db()

    # Detect events
    events = detect_events(LOG_FILE)
    print("Detected events:", events)  # debug output

    for event_type, line in events:
        severity = get_severity(event_type, rules)
        save_incident(event_type, severity)
        collect_evidence(event_type, severity, line)
        alert(event_type, severity)

    print("IR-ATS execution completed.")

if __name__ == "__main__":
    main()
