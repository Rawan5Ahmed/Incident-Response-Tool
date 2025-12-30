"""
IR Workflow Manager
Manages incident lifecycle through Detection → Analysis → Containment → Recovery
"""

from datetime import datetime
from typing import Optional, Dict, List
from logdb import LogDB
from event_classifier import EventClassifier


class IRWorkflowManager:
    """Manages IR workflow stages for incidents"""
    
    def __init__(self, db: LogDB):
        self.db = db
        self.classifier = EventClassifier()
    
    def create_incident_from_log(self, log_id: int, message: str, log_level: Optional[str], 
                                  anomaly_score: Optional[float]) -> Optional[int]:
        """
        Create an incident from a log entry
        
        Args:
            log_id: ID of the log entry
            message: Log message
            log_level: Log level (ERROR, WARNING, etc.)
            anomaly_score: Anomaly score from ML model
        
        Returns:
            Incident ID if created, None otherwise
        """
        # Classify the event
        event_type, severity = self.classifier.classify(message, log_level, anomaly_score)
        
        # Only create incidents for Medium and High severity
        if severity in ('Medium', 'High'):
            detected_at = datetime.utcnow().isoformat()
            incident_id = self.db.create_incident(log_id, event_type, severity, detected_at)
            return incident_id
        
        return None
    
    def auto_create_incidents_from_anomalies(self, anomalies: List[Dict]) -> List[int]:
        """
        Auto-create incidents from anomaly detection results
        
        Args:
            anomalies: List of anomaly dicts with 'id', 'message', 'score'
        
        Returns:
            List of created incident IDs
        """
        created_incidents = []
        
        for anomaly in anomalies:
            log_id = anomaly.get('id')
            message = anomaly.get('message', '')
            score = anomaly.get('score', 0)
            
            # Get log level from database
            log_entry = self.db._conn().execute(
                "SELECT level FROM logs WHERE id = ?", (log_id,)
            ).fetchone()
            log_level = log_entry[0] if log_entry else None
            
            incident_id = self.create_incident_from_log(log_id, message, log_level, score)
            if incident_id:
                created_incidents.append(incident_id)
        
        return created_incidents
    
    def advance_to_analysis(self, incident_id: int) -> bool:
        """Move incident from Detection to Analysis stage"""
        timestamp = datetime.utcnow().isoformat()
        return self.db.update_incident_stage(incident_id, 'Analysis', timestamp)
    
    def advance_to_containment(self, incident_id: int) -> bool:
        """Move incident from Analysis to Containment stage"""
        timestamp = datetime.utcnow().isoformat()
        return self.db.update_incident_stage(incident_id, 'Containment', timestamp)
    
    def advance_to_recovery(self, incident_id: int) -> bool:
        """Move incident from Containment to Recovery stage"""
        timestamp = datetime.utcnow().isoformat()
        return self.db.update_incident_stage(incident_id, 'Recovery', timestamp)
    
    def get_incident_with_log(self, incident_id: int) -> Optional[Dict]:
        """Get incident details with associated log entry"""
        incident = self.db.get_incident(incident_id)
        if not incident:
            return None
        
        # Fetch associated log
        log_id = incident['log_id']
        with self.db._conn() as c:
            log_row = c.execute(
                "SELECT id, ts, level, message, raw, anomaly_score FROM logs WHERE id = ?",
                (log_id,)
            ).fetchone()
            
            if log_row:
                incident['log'] = {
                    'id': log_row[0],
                    'ts': log_row[1],
                    'level': log_row[2],
                    'message': log_row[3],
                    'raw': log_row[4],
                    'anomaly_score': log_row[5]
                }
        
        # Add event description
        incident['event_description'] = self.classifier.get_event_description(
            incident['event_type']
        )
        
        return incident
    
    def get_workflow_summary(self) -> Dict:
        """Get summary of incidents by stage"""
        all_incidents = self.db.get_incidents()
        
        summary = {
            'Detection': 0,
            'Analysis': 0,
            'Containment': 0,
            'Recovery': 0,
            'total': len(all_incidents),
            'by_severity': {
                'High': 0,
                'Medium': 0,
                'Low': 0
            }
        }
        
        for incident in all_incidents:
            stage = incident.get('current_stage', 'Detection')
            severity = incident.get('severity', 'Low')
            
            if stage in summary:
                summary[stage] += 1
            
            if severity in summary['by_severity']:
                summary['by_severity'][severity] += 1
        
        return summary
    
    def get_active_incidents(self, limit: int = 50) -> List[Dict]:
        """Get active incidents (not in Recovery stage) with details"""
        all_incidents = self.db.get_incidents(limit=limit)
        
        # Filter out completed incidents and enrich with details
        active = []
        for incident in all_incidents:
            if incident['current_stage'] != 'Recovery':
                # Add event description
                incident['event_description'] = self.classifier.get_event_description(
                    incident['event_type']
                )
                active.append(incident)
        
        return active
    
    def get_timeline(self, incident_id: int) -> List[Dict]:
        """Get timeline of workflow stages for an incident"""
        incident = self.db.get_incident(incident_id)
        if not incident:
            return []
        
        timeline = []
        
        stages = [
            ('Detection', incident.get('detected_at')),
            ('Analysis', incident.get('analyzed_at')),
            ('Containment', incident.get('contained_at')),
            ('Recovery', incident.get('recovered_at'))
        ]
        
        for stage_name, timestamp in stages:
            if timestamp:
                timeline.append({
                    'stage': stage_name,
                    'timestamp': timestamp,
                    'completed': True
                })
            else:
                timeline.append({
                    'stage': stage_name,
                    'timestamp': None,
                    'completed': False
                })
        
        return timeline


if __name__ == '__main__':
    # Test the workflow manager
    from logdb import LogDB
    
    db = LogDB('test_workflow.db')
    manager = IRWorkflowManager(db)
    
    # Insert a test log
    test_log = {
        'ts': datetime.utcnow().isoformat(),
        'level': 'ERROR',
        'message': 'Failed password for admin from 192.168.1.100',
        'raw': 'Failed password for admin from 192.168.1.100'
    }
    db.insert_log(test_log)
    
    # Create incident
    incident_id = manager.create_incident_from_log(1, test_log['message'], test_log['level'], 0.9)
    print(f"Created incident: {incident_id}")
    
    # Get workflow summary
    summary = manager.get_workflow_summary()
    print(f"Workflow summary: {summary}")
    
    # Advance stages
    manager.advance_to_analysis(incident_id)
    manager.advance_to_containment(incident_id)
    
    # Get timeline
    timeline = manager.get_timeline(incident_id)
    print(f"Timeline: {timeline}")
