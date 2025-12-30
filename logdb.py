import sqlite3
import json
from datetime import datetime

CREATE_SQL = """
CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT,
    level TEXT,
    message TEXT,
    raw TEXT,
    added_at TEXT,
    anomaly_score REAL,
    is_anomaly INTEGER
)
"""

INCIDENTS_SQL = """
CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    log_id INTEGER,
    event_type TEXT,
    severity TEXT,
    
    -- IR Workflow Timestamps
    detected_at TEXT,
    analyzed_at TEXT,
    contained_at TEXT,
    recovered_at TEXT,
    
    -- Workflow Status
    current_stage TEXT,
    
    -- Evidence
    evidence_folder TEXT,
    
    -- Containment
    containment_actions TEXT,
    containment_status TEXT,
    
    FOREIGN KEY (log_id) REFERENCES logs(id)
)
"""

class LogDB:
    def __init__(self, path='logs.db'):
        self.path = path
        self._init_db()

    def _conn(self):
        return sqlite3.connect(self.path, check_same_thread=False)

    def _init_db(self):
        with self._conn() as c:
            c.execute(CREATE_SQL)
            c.execute(INCIDENTS_SQL)

    def insert_log(self, parsed):
        with self._conn() as c:
            c.execute(
                "INSERT INTO logs (ts, level, message, raw, added_at, anomaly_score, is_anomaly) VALUES (?,?,?,?,?,?,?)",
                (parsed.get('ts'), parsed.get('level'), parsed.get('message'), parsed.get('raw'), datetime.utcnow().isoformat(), None, 0)
            )

    def insert_logs_bulk(self, parsed_list):
        if not parsed_list: return
        now_str = datetime.utcnow().isoformat()
        params = []
        for p in parsed_list:
            params.append((p.get('ts'), p.get('level'), p.get('message'), p.get('raw'), now_str, None, 0))
        
        with self._conn() as c:
            c.executemany(
                "INSERT INTO logs (ts, level, message, raw, added_at, anomaly_score, is_anomaly) VALUES (?,?,?,?,?,?,?)",
                params
            )

    def get_logs(self, limit=500):
        with self._conn() as c:
            rows = c.execute("SELECT id, ts, level, message, raw, added_at, anomaly_score, is_anomaly FROM logs ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
            keys = ['id','ts','level','message','raw','added_at','anomaly_score','is_anomaly']
            return [dict(zip(keys,r)) for r in rows]

    def get_severity_counts(self):
        with self._conn() as c:
            # Count by score ranges
            high = c.execute("SELECT count(*) FROM logs WHERE anomaly_score > 0.8").fetchone()[0]
            medium = c.execute("SELECT count(*) FROM logs WHERE anomaly_score > 0.5 AND anomaly_score <= 0.8").fetchone()[0]
            low = c.execute("SELECT count(*) FROM logs WHERE anomaly_score <= 0.5 AND anomaly_score IS NOT NULL").fetchone()[0]
            pending = c.execute("SELECT count(*) FROM logs WHERE anomaly_score IS NULL").fetchone()[0]
            return {'High': high, 'Medium': medium, 'Low': low, 'Pending': pending}

    def update_anomalies(self, updates):
        # updates: list of (id, score, is_anomaly)
        with self._conn() as c:
            c.executemany("UPDATE logs SET anomaly_score=?, is_anomaly=? WHERE id=?", [(u[1], u[2], u[0]) for u in updates])

    def get_messages(self, limit=None):
        q = "SELECT id, message FROM logs ORDER BY id DESC"
        if limit:
            q += " LIMIT %d" % int(limit)
        with self._conn() as c:
            return c.execute(q).fetchall()

    def clear_logs(self):
        with self._conn() as c:
            # Delete child records first due to foreign key constraints
            c.execute("DELETE FROM incidents")
            c.execute("DELETE FROM logs")
            # Reset auto-increment counters
            c.execute("DELETE FROM sqlite_sequence WHERE name='logs'")
            c.execute("DELETE FROM sqlite_sequence WHERE name='incidents'")
        
        # Remove model file so training starts fresh
        import os
        if os.path.exists('model.joblib'):
            try:
                os.remove('model.joblib')
            except: pass

        # VACUUM must be done outside a transaction
        try:
            conn = self._conn()
            conn.isolation_level = None
            conn.execute("VACUUM")
            conn.close()
        except Exception:
            pass
    
    # Incident Management Methods
    def create_incident(self, log_id, event_type, severity, detected_at):
        """Create a new incident in Detection stage"""
        with self._conn() as c:
            cursor = c.execute(
                """INSERT INTO incidents 
                   (log_id, event_type, severity, detected_at, current_stage, containment_status) 
                   VALUES (?, ?, ?, ?, 'Detection', 'pending')""",
                (log_id, event_type, severity, detected_at)
            )
            return cursor.lastrowid
    
    def get_incident(self, incident_id):
        """Get a single incident by ID"""
        with self._conn() as c:
            row = c.execute(
                """SELECT id, log_id, event_type, severity, detected_at, analyzed_at, 
                          contained_at, recovered_at, current_stage, evidence_folder, 
                          containment_actions, containment_status 
                   FROM incidents WHERE id = ?""",
                (incident_id,)
            ).fetchone()
            if row:
                keys = ['id', 'log_id', 'event_type', 'severity', 'detected_at', 'analyzed_at',
                        'contained_at', 'recovered_at', 'current_stage', 'evidence_folder',
                        'containment_actions', 'containment_status']
                return dict(zip(keys, row))
            return None
    
    def get_incidents(self, stage=None, limit=100):
        """Get all incidents, optionally filtered by stage"""
        with self._conn() as c:
            if stage:
                rows = c.execute(
                    """SELECT id, log_id, event_type, severity, detected_at, analyzed_at, 
                              contained_at, recovered_at, current_stage, evidence_folder, 
                              containment_actions, containment_status 
                       FROM incidents WHERE current_stage = ? ORDER BY id DESC LIMIT ?""",
                    (stage, limit)
                ).fetchall()
            else:
                rows = c.execute(
                    """SELECT id, log_id, event_type, severity, detected_at, analyzed_at, 
                              contained_at, recovered_at, current_stage, evidence_folder, 
                              containment_actions, containment_status 
                       FROM incidents ORDER BY id DESC LIMIT ?""",
                    (limit,)
                ).fetchall()
            
            keys = ['id', 'log_id', 'event_type', 'severity', 'detected_at', 'analyzed_at',
                    'contained_at', 'recovered_at', 'current_stage', 'evidence_folder',
                    'containment_actions', 'containment_status']
            return [dict(zip(keys, r)) for r in rows]
    
    def update_incident_stage(self, incident_id, new_stage, timestamp):
        """Advance incident to next stage with timestamp"""
        stage_field_map = {
            'Analysis': 'analyzed_at',
            'Containment': 'contained_at',
            'Recovery': 'recovered_at'
        }
        
        field = stage_field_map.get(new_stage)
        if not field:
            return False
        
        with self._conn() as c:
            cursor = c.execute(
                f"UPDATE incidents SET current_stage = ?, {field} = ? WHERE id = ?",
                (new_stage, timestamp, incident_id)
            )
            return cursor.rowcount > 0
    
    def update_incident_evidence(self, incident_id, evidence_folder):
        """Update evidence folder path for incident"""
        with self._conn() as c:
            c.execute(
                "UPDATE incidents SET evidence_folder = ? WHERE id = ?",
                (evidence_folder, incident_id)
            )
    
    def update_incident_containment(self, incident_id, actions_json, status):
        """Update containment actions and status"""
        with self._conn() as c:
            c.execute(
                "UPDATE incidents SET containment_actions = ?, containment_status = ? WHERE id = ?",
                (actions_json, status, incident_id)
            )
