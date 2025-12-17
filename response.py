def alert(event, severity):
    if severity == "High":
        message = f"[ALERT] High severity incident detected: {event}"
        print(message)
        with open("alerts.txt", "a") as f:
            f.write(message + "\n")
