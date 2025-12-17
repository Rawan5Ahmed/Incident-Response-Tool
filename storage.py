import sqlite3
from datetime import datetime

def init_db():
    conn = sqlite3.connect("incidents.db")
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event TEXT,
            severity TEXT,
            timestamp TEXT
        )
    """)
    conn.commit()
    conn.close()

def save_incident(event, severity):
    conn = sqlite3.connect("incidents.db")
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO incidents (event, severity, timestamp) VALUES (?, ?, ?)",
        (event, severity, datetime.now().isoformat())
    )
    conn.commit()
    conn.close()
