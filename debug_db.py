import sqlite3
import os

db_path = 'd:/cybersecurity tool/logs.db'
if not os.path.exists(db_path):
    print("DB not found at", db_path)
    exit()

conn = sqlite3.connect(db_path)
c = conn.cursor()

print("--- Unique Levels in DB ---")
try:
    c.execute("SELECT level, COUNT(*) FROM logs GROUP BY level")
    for row in c.fetchall():
        print(row)
except Exception as e:
    print("Error querying levels:", e)

print("\n--- First 5 Rows Raw ---")
try:
    c.execute("SELECT * FROM logs LIMIT 5")
    for row in c.fetchall():
        print(row)
except Exception as e:
    print("Error querying rows:", e)

conn.close()
