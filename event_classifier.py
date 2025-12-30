"""
Event Type Classifier for Security Events
Classifies log messages into security event types with severity levels
"""

import re
from typing import Tuple, Optional


class EventClassifier:
    """Classifies security events based on log content"""
    
    # Event type patterns (regex, event_type, base_severity)
    PATTERNS = [
        # Authentication Events
        (r'failed password|authentication failure|bad credentials|invalid password|login failed', 
         'failed_login', 'Medium'),
        (r'successful login|logged in|authentication successful', 
         'successful_login', 'Low'),
        (r'account locked|too many failed attempts|brute force', 
         'account_lockout', 'High'),
        
        # User/Account Management
        (r'user add|new user created|account created|useradd', 
         'user_creation', 'Medium'),
        (r'user deleted|account deleted|userdel', 
         'user_deletion', 'Medium'),
        (r'password changed|password reset|passwd', 
         'password_change', 'Low'),
        (r'group add|added to group|administrators|sudo', 
         'privilege_escalation', 'High'),
        
        # Process Events
        (r'process created|new process|exec|spawn', 
         'process_creation', 'Low'),
        (r'suspicious process|malicious|trojan|backdoor', 
         'suspicious_process', 'High'),
        (r'process terminated|killed|stopped', 
         'process_termination', 'Low'),
        
        # Network Events
        (r'connection refused|connection timeout|network error', 
         'network_error', 'Medium'),
        (r'port scan|scanning|nmap|masscan', 
         'port_scan', 'High'),
        (r'unusual traffic|anomalous connection|suspicious ip', 
         'network_anomaly', 'High'),
        
        # Web/HTTP Events
        (r'404|not found|file not found', 
         'web_scanning', 'Medium'),
        (r'500|internal server error|server crash', 
         'server_error', 'Medium'),
        (r'sql injection|union select|script>|xss|code injection', 
         'web_attack', 'High'),
        
        # File Events
        (r'file deleted|removed|unlink', 
         'file_deletion', 'Low'),
        (r'file modified|changed|altered', 
         'file_modification', 'Low'),
        (r'unauthorized access|permission denied|access violation', 
         'file_access_violation', 'Medium'),
        (r'ransomware|encrypted|crypto', 
         'ransomware_activity', 'High'),
        
        # System Events
        (r'segmentation fault|segfault|core dump|crash', 
         'system_crash', 'High'),
        (r'disk full|out of space|no space left', 
         'disk_full', 'Medium'),
        (r'service stopped|daemon failed|service unavailable', 
         'service_failure', 'Medium'),
        
        # Security Events
        (r'firewall|blocked|dropped|denied', 
         'firewall_block', 'Low'),
        (r'malware|virus|infected', 
         'malware_detection', 'High'),
        (r'audit log cleared|log deleted|evidence tampering', 
         'log_tampering', 'High'),
    ]
    
    # Windows Event ID to event type mapping
    WINDOWS_EVENT_MAP = {
        '4624': ('successful_login', 'Low'),
        '4625': ('failed_login', 'Medium'),
        '4720': ('user_creation', 'Medium'),
        '4726': ('user_deletion', 'Medium'),
        '4732': ('privilege_escalation', 'High'),
        '4688': ('process_creation', 'Low'),
        '1102': ('log_tampering', 'High'),
        '4698': ('scheduled_task_creation', 'Medium'),
    }
    
    @classmethod
    def classify(cls, message: str, log_level: Optional[str] = None, anomaly_score: Optional[float] = None) -> Tuple[str, str]:
        """
        Classify a log message into event type and severity
        
        Args:
            message: Log message text
            log_level: Original log level (ERROR, WARNING, INFO, etc.)
            anomaly_score: ML-based anomaly score (0-1, higher = more anomalous)
        
        Returns:
            Tuple of (event_type, severity)
            event_type: String identifier for the event
            severity: 'High', 'Medium', or 'Low'
        """
        message_lower = message.lower()
        
        # Check for Windows Event IDs first
        event_id_match = re.search(r'event\s*id[:\s]+(\d+)', message_lower)
        if event_id_match:
            event_id = event_id_match.group(1)
            if event_id in cls.WINDOWS_EVENT_MAP:
                return cls.WINDOWS_EVENT_MAP[event_id]
        
        # Pattern matching
        for pattern, event_type, base_severity in cls.PATTERNS:
            if re.search(pattern, message_lower):
                # Adjust severity based on anomaly score if available
                severity = cls._adjust_severity(base_severity, anomaly_score, log_level)
                return event_type, severity
        
        # Fallback: use anomaly score or log level
        if anomaly_score is not None:
            if anomaly_score > 0.8:
                return 'unknown_anomaly', 'High'
            elif anomaly_score > 0.5:
                return 'unknown_anomaly', 'Medium'
            else:
                return 'normal_activity', 'Low'
        
        # Final fallback based on log level
        if log_level:
            level_upper = log_level.upper()
            if level_upper in ('ERROR', 'CRITICAL'):
                return 'unknown_error', 'Medium'
            elif level_upper == 'WARNING':
                return 'unknown_warning', 'Low'
        
        return 'normal_activity', 'Low'
    
    @classmethod
    def _adjust_severity(cls, base_severity: str, anomaly_score: Optional[float], log_level: Optional[str]) -> str:
        """Adjust severity based on anomaly score and log level"""
        severity_score = {'Low': 1, 'Medium': 2, 'High': 3}
        current_score = severity_score.get(base_severity, 1)
        
        # Boost severity if high anomaly score
        if anomaly_score is not None and anomaly_score > 0.8:
            current_score = max(current_score, 3)  # High
        elif anomaly_score is not None and anomaly_score > 0.5:
            current_score = max(current_score, 2)  # Medium
        
        # Boost severity if ERROR/CRITICAL log level
        if log_level and log_level.upper() in ('ERROR', 'CRITICAL'):
            current_score = max(current_score, 2)  # At least Medium
        
        # Convert back to severity string
        for sev, score in severity_score.items():
            if score == current_score:
                return sev
        
        return base_severity
    
    @classmethod
    def get_event_description(cls, event_type: str) -> str:
        """Get human-readable description for event type"""
        descriptions = {
            'failed_login': 'Failed Login Attempt',
            'successful_login': 'Successful Login',
            'account_lockout': 'Account Lockout',
            'user_creation': 'New User Account Created',
            'user_deletion': 'User Account Deleted',
            'password_change': 'Password Changed',
            'privilege_escalation': 'Privilege Escalation',
            'process_creation': 'Process Created',
            'suspicious_process': 'Suspicious Process Detected',
            'process_termination': 'Process Terminated',
            'network_error': 'Network Error',
            'port_scan': 'Port Scanning Activity',
            'network_anomaly': 'Network Anomaly',
            'web_scanning': 'Web Scanning/Enumeration',
            'server_error': 'Server Error',
            'web_attack': 'Web Attack Detected',
            'file_deletion': 'File Deleted',
            'file_modification': 'File Modified',
            'file_access_violation': 'Unauthorized File Access',
            'ransomware_activity': 'Ransomware Activity',
            'system_crash': 'System Crash',
            'disk_full': 'Disk Space Critical',
            'service_failure': 'Service Failure',
            'firewall_block': 'Firewall Block',
            'malware_detection': 'Malware Detected',
            'log_tampering': 'Log Tampering Detected',
            'scheduled_task_creation': 'Scheduled Task Created',
            'unknown_anomaly': 'Unknown Anomaly',
            'unknown_error': 'Unknown Error',
            'unknown_warning': 'Unknown Warning',
            'normal_activity': 'Normal Activity',
        }
        return descriptions.get(event_type, event_type.replace('_', ' ').title())


if __name__ == '__main__':
    # Test cases
    test_cases = [
        "Failed password for user admin from 192.168.1.100",
        "User account 'hacker' created",
        "SQL Injection detected: ' OR 1=1",
        "404 Not Found: /admin/config.php",
        "Process terminated: PID 1234",
        "EventID: 4625 - Failed login attempt",
    ]
    
    print("Event Classifier Test Cases:")
    print("-" * 60)
    for msg in test_cases:
        event_type, severity = EventClassifier.classify(msg, anomaly_score=0.9)
        desc = EventClassifier.get_event_description(event_type)
        print(f"Message: {msg}")
        print(f"  → Type: {event_type} | Severity: {severity} | Desc: {desc}")
        print()
