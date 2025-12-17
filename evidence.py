import os
from datetime import datetime

def collect_evidence(event, severity, log_line):
    folder = f"evidence/incident_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    os.makedirs(folder, exist_ok=True)

    with open(f"{folder}/log.txt", "w") as f:
        f.write(log_line)

    with open(f"{folder}/metadata.txt", "w") as f:
        f.write(f"Event: {event}\nSeverity: {severity}\nTime: {datetime.now()}")
