"""
Evidence Collector
Automatically generates evidence folders for incidents with system metadata
"""

import os
import platform
import subprocess
import json
from datetime import datetime
from typing import Dict, Optional


class EvidenceCollector:
    """Collects and organizes evidence for security incidents"""
    
    def __init__(self, base_path: str = './evidence'):
        self.base_path = base_path
        os.makedirs(base_path, exist_ok=True)
    
    def create_evidence_folder(self, incident_id: int, incident_data: Dict) -> str:
        """
        Create evidence folder for an incident
        
        Args:
            incident_id: Incident ID
            incident_data: Incident details including log, event_type, severity
        
        Returns:
            Path to created evidence folder
        """
        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        folder_name = f"incident_{incident_id}_{timestamp}"
        folder_path = os.path.join(self.base_path, folder_name)
        
        os.makedirs(folder_path, exist_ok=True)
        
        # Generate all evidence files
        self._generate_incident_report(folder_path, incident_id, incident_data)
        self._collect_system_info(folder_path)
        self._collect_process_list(folder_path)
        self._collect_network_connections(folder_path)
        self._collect_relevant_logs(folder_path, incident_data)
        self._generate_metadata(folder_path, incident_id, incident_data)
        
        return folder_path
    
    def _generate_incident_report(self, folder_path: str, incident_id: int, incident_data: Dict):
        """Generate human-readable incident report"""
        report_path = os.path.join(folder_path, 'incident_report.txt')
        
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write("=" * 70 + "\n")
            f.write("INCIDENT RESPONSE EVIDENCE REPORT\n")
            f.write("=" * 70 + "\n\n")
            
            f.write(f"Incident ID: {incident_id}\n")
            f.write(f"Generated: {datetime.utcnow().isoformat()}\n\n")
            
            f.write("-" * 70 + "\n")
            f.write("INCIDENT DETAILS\n")
            f.write("-" * 70 + "\n")
            f.write(f"Event Type: {incident_data.get('event_type', 'Unknown')}\n")
            f.write(f"Event Description: {incident_data.get('event_description', 'N/A')}\n")
            f.write(f"Severity: {incident_data.get('severity', 'Unknown')}\n")
            f.write(f"Current Stage: {incident_data.get('current_stage', 'Detection')}\n\n")
            
            f.write("-" * 70 + "\n")
            f.write("IR WORKFLOW TIMELINE\n")
            f.write("-" * 70 + "\n")
            f.write(f"Detection:   {incident_data.get('detected_at', 'N/A')}\n")
            f.write(f"Analysis:    {incident_data.get('analyzed_at', 'Pending')}\n")
            f.write(f"Containment: {incident_data.get('contained_at', 'Pending')}\n")
            f.write(f"Recovery:    {incident_data.get('recovered_at', 'Pending')}\n\n")
            
            if 'log' in incident_data:
                log = incident_data['log']
                f.write("-" * 70 + "\n")
                f.write("LOG ENTRY\n")
                f.write("-" * 70 + "\n")
                f.write(f"Log ID: {log.get('id', 'N/A')}\n")
                f.write(f"Timestamp: {log.get('ts', 'N/A')}\n")
                f.write(f"Level: {log.get('level', 'N/A')}\n")
                f.write(f"Anomaly Score: {log.get('anomaly_score', 'N/A')}\n")
                f.write(f"Message: {log.get('message', 'N/A')}\n\n")
                f.write("Raw Log:\n")
                f.write(log.get('raw', 'N/A') + "\n\n")
            
            if incident_data.get('containment_actions'):
                f.write("-" * 70 + "\n")
                f.write("CONTAINMENT ACTIONS\n")
                f.write("-" * 70 + "\n")
                f.write(f"Status: {incident_data.get('containment_status', 'N/A')}\n")
                f.write(f"Actions: {incident_data.get('containment_actions', 'None')}\n\n")
            
            f.write("=" * 70 + "\n")
            f.write("END OF REPORT\n")
            f.write("=" * 70 + "\n")
    
    def _collect_system_info(self, folder_path: str):
        """Collect system information"""
        info_path = os.path.join(folder_path, 'system_info.txt')
        
        with open(info_path, 'w', encoding='utf-8') as f:
            f.write("SYSTEM INFORMATION\n")
            f.write("=" * 50 + "\n\n")
            
            f.write(f"Operating System: {platform.system()}\n")
            f.write(f"OS Version: {platform.version()}\n")
            f.write(f"OS Release: {platform.release()}\n")
            f.write(f"Architecture: {platform.machine()}\n")
            f.write(f"Hostname: {platform.node()}\n")
            f.write(f"Processor: {platform.processor()}\n")
            f.write(f"Python Version: {platform.python_version()}\n")
            f.write(f"Collection Time: {datetime.utcnow().isoformat()}\n")
    
    def _collect_process_list(self, folder_path: str):
        """Collect running processes snapshot"""
        process_path = os.path.join(folder_path, 'processes.txt')
        
        try:
            if platform.system() == 'Windows':
                result = subprocess.run(
                    ['tasklist', '/V', '/FO', 'CSV'],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
            else:
                result = subprocess.run(
                    ['ps', 'aux'],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
            
            with open(process_path, 'w', encoding='utf-8') as f:
                f.write("RUNNING PROCESSES SNAPSHOT\n")
                f.write("=" * 50 + "\n\n")
                f.write(result.stdout)
        
        except Exception as e:
            with open(process_path, 'w', encoding='utf-8') as f:
                f.write(f"Error collecting process list: {str(e)}\n")
    
    def _collect_network_connections(self, folder_path: str):
        """Collect active network connections"""
        network_path = os.path.join(folder_path, 'network_connections.txt')
        
        try:
            if platform.system() == 'Windows':
                result = subprocess.run(
                    ['netstat', '-ano'],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
            else:
                result = subprocess.run(
                    ['netstat', '-tunapo'],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
            
            with open(network_path, 'w', encoding='utf-8') as f:
                f.write("ACTIVE NETWORK CONNECTIONS\n")
                f.write("=" * 50 + "\n\n")
                f.write(result.stdout)
        
        except Exception as e:
            with open(network_path, 'w', encoding='utf-8') as f:
                f.write(f"Error collecting network connections: {str(e)}\n")
    
    def _collect_relevant_logs(self, folder_path: str, incident_data: Dict):
        """Save relevant log entries"""
        logs_path = os.path.join(folder_path, 'relevant_logs.txt')
        
        with open(logs_path, 'w', encoding='utf-8') as f:
            f.write("RELEVANT LOG ENTRIES\n")
            f.write("=" * 50 + "\n\n")
            
            if 'log' in incident_data:
                log = incident_data['log']
                f.write(f"Primary Log Entry (ID: {log.get('id')})\n")
                f.write("-" * 50 + "\n")
                f.write(f"Timestamp: {log.get('ts', 'N/A')}\n")
                f.write(f"Level: {log.get('level', 'N/A')}\n")
                f.write(f"Message: {log.get('message', 'N/A')}\n")
                f.write(f"Raw: {log.get('raw', 'N/A')}\n\n")
            else:
                f.write("No log data available\n")
    
    def _generate_metadata(self, folder_path: str, incident_id: int, incident_data: Dict):
        """Generate machine-readable metadata JSON"""
        metadata_path = os.path.join(folder_path, 'metadata.json')
        
        metadata = {
            'incident_id': incident_id,
            'collection_time': datetime.utcnow().isoformat(),
            'collector_version': '1.0',
            'incident_data': {
                'event_type': incident_data.get('event_type'),
                'severity': incident_data.get('severity'),
                'current_stage': incident_data.get('current_stage'),
                'detected_at': incident_data.get('detected_at'),
                'analyzed_at': incident_data.get('analyzed_at'),
                'contained_at': incident_data.get('contained_at'),
                'recovered_at': incident_data.get('recovered_at'),
            },
            'system_info': {
                'os': platform.system(),
                'os_version': platform.version(),
                'hostname': platform.node(),
                'architecture': platform.machine(),
            },
            'evidence_files': [
                'incident_report.txt',
                'system_info.txt',
                'processes.txt',
                'network_connections.txt',
                'relevant_logs.txt',
                'metadata.json'
            ]
        }
        
        with open(metadata_path, 'w', encoding='utf-8') as f:
            json.dump(metadata, f, indent=2)


if __name__ == '__main__':
    # Test evidence collection
    collector = EvidenceCollector('./test_evidence')
    
    test_incident = {
        'event_type': 'failed_login',
        'event_description': 'Failed Login Attempt',
        'severity': 'High',
        'current_stage': 'Analysis',
        'detected_at': datetime.utcnow().isoformat(),
        'analyzed_at': datetime.utcnow().isoformat(),
        'log': {
            'id': 123,
            'ts': datetime.utcnow().isoformat(),
            'level': 'ERROR',
            'message': 'Failed password for admin from 192.168.1.100',
            'raw': 'Failed password for admin from 192.168.1.100',
            'anomaly_score': 0.95
        }
    }
    
    folder = collector.create_evidence_folder(1, test_incident)
    print(f"Evidence folder created: {folder}")
