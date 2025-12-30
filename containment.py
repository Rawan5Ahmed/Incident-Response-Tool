"""
Containment Actions Module
Simulates containment actions for security incidents (SAFE MODE - no actual execution)
"""

import re
import json
from datetime import datetime
from typing import Dict, List, Optional, Tuple


class ContainmentEngine:
    """Manages containment actions for incidents (SIMULATE MODE ONLY)"""
    
    def __init__(self, mode: str = 'simulate'):
        """
        Initialize containment engine
        
        Args:
            mode: 'simulate' (log only, no execution) - ONLY SAFE MODE SUPPORTED
        """
        if mode != 'simulate':
            raise ValueError("Only 'simulate' mode is supported for safety")
        self.mode = mode
    
    def block_ip(self, ip_address: str, incident_id: int) -> Dict:
        """
        Simulate blocking an IP address
        
        Args:
            ip_address: IP address to block
            incident_id: Associated incident ID
        
        Returns:
            Action result dict
        """
        # Validate IP format
        if not self._is_valid_ip(ip_address):
            return {
                'action': 'block_ip',
                'status': 'failed',
                'reason': 'Invalid IP address format',
                'ip': ip_address,
                'timestamp': datetime.utcnow().isoformat()
            }
        
        # Simulate the action
        command = f"netsh advfirewall firewall add rule name=\"Block_IR_{incident_id}\" dir=in action=block remoteip={ip_address}"
        
        return {
            'action': 'block_ip',
            'status': 'simulated',
            'ip': ip_address,
            'command': command,
            'incident_id': incident_id,
            'timestamp': datetime.utcnow().isoformat(),
            'note': 'Action simulated only - no actual firewall rule created'
        }
    
    def kill_process(self, pid: int, process_name: str, incident_id: int) -> Dict:
        """
        Simulate terminating a suspicious process
        
        Args:
            pid: Process ID
            process_name: Process name
            incident_id: Associated incident ID
        
        Returns:
            Action result dict
        """
        import platform
        
        if platform.system() == 'Windows':
            command = f"taskkill /PID {pid} /F"
        else:
            command = f"kill -9 {pid}"
        
        return {
            'action': 'kill_process',
            'status': 'simulated',
            'pid': pid,
            'process_name': process_name,
            'command': command,
            'incident_id': incident_id,
            'timestamp': datetime.utcnow().isoformat(),
            'note': 'Action simulated only - process not terminated'
        }
    
    def quarantine_file(self, filepath: str, incident_id: int) -> Dict:
        """
        Simulate quarantining a suspicious file
        
        Args:
            filepath: Path to file to quarantine
            incident_id: Associated incident ID
        
        Returns:
            Action result dict
        """
        quarantine_path = f"./quarantine/incident_{incident_id}/{filepath.split('/')[-1]}"
        
        return {
            'action': 'quarantine_file',
            'status': 'simulated',
            'original_path': filepath,
            'quarantine_path': quarantine_path,
            'incident_id': incident_id,
            'timestamp': datetime.utcnow().isoformat(),
            'note': 'Action simulated only - file not moved'
        }
    
    def isolate_host(self, hostname: str, incident_id: int) -> Dict:
        """
        Simulate network isolation of a compromised host
        
        Args:
            hostname: Hostname to isolate
            incident_id: Associated incident ID
        
        Returns:
            Action result dict
        """
        import platform
        
        if platform.system() == 'Windows':
            command = f"netsh interface set interface \"Ethernet\" admin=disable"
        else:
            command = f"ifconfig eth0 down"
        
        return {
            'action': 'isolate_host',
            'status': 'simulated',
            'hostname': hostname,
            'command': command,
            'incident_id': incident_id,
            'timestamp': datetime.utcnow().isoformat(),
            'note': 'Action simulated only - network not disabled'
        }
    
    def disable_user_account(self, username: str, incident_id: int) -> Dict:
        """
        Simulate disabling a compromised user account
        
        Args:
            username: Username to disable
            incident_id: Associated incident ID
        
        Returns:
            Action result dict
        """
        import platform
        
        if platform.system() == 'Windows':
            command = f"net user {username} /active:no"
        else:
            command = f"usermod -L {username}"
        
        return {
            'action': 'disable_user_account',
            'status': 'simulated',
            'username': username,
            'command': command,
            'incident_id': incident_id,
            'timestamp': datetime.utcnow().isoformat(),
            'note': 'Action simulated only - account not disabled'
        }
    
    def recommend_actions(self, event_type: str, message: str) -> List[Dict]:
        """
        Recommend containment actions based on event type and message
        
        Args:
            event_type: Type of security event
            message: Log message
        
        Returns:
            List of recommended action dicts
        """
        recommendations = []
        
        # Extract IP addresses from message
        ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', message)
        
        # Event-specific recommendations
        if event_type in ('failed_login', 'account_lockout'):
            if ips:
                recommendations.append({
                    'action': 'block_ip',
                    'params': {'ip_address': ips[0]},
                    'reason': 'Multiple failed login attempts from this IP',
                    'priority': 'High'
                })
        
        elif event_type == 'suspicious_process':
            recommendations.append({
                'action': 'kill_process',
                'params': {'pid': 'UNKNOWN', 'process_name': 'suspicious'},
                'reason': 'Suspicious process detected',
                'priority': 'High'
            })
        
        elif event_type in ('web_attack', 'sql_injection'):
            if ips:
                recommendations.append({
                    'action': 'block_ip',
                    'params': {'ip_address': ips[0]},
                    'reason': 'Web attack detected from this IP',
                    'priority': 'High'
                })
        
        elif event_type == 'privilege_escalation':
            # Extract username if possible
            user_match = re.search(r'user[:\s]+(\w+)', message, re.IGNORECASE)
            if user_match:
                recommendations.append({
                    'action': 'disable_user_account',
                    'params': {'username': user_match.group(1)},
                    'reason': 'Unauthorized privilege escalation detected',
                    'priority': 'High'
                })
        
        elif event_type in ('malware_detection', 'ransomware_activity'):
            recommendations.append({
                'action': 'isolate_host',
                'params': {'hostname': 'localhost'},
                'reason': 'Malware detected - isolate to prevent spread',
                'priority': 'Critical'
            })
        
        return recommendations
    
    def execute_action(self, action_type: str, params: Dict, incident_id: int) -> Dict:
        """
        Execute a containment action (SIMULATE MODE)
        
        Args:
            action_type: Type of action ('block_ip', 'kill_process', etc.)
            params: Action parameters
            incident_id: Associated incident ID
        
        Returns:
            Action result dict
        """
        action_map = {
            'block_ip': lambda: self.block_ip(params.get('ip_address', ''), incident_id),
            'kill_process': lambda: self.kill_process(
                params.get('pid', 0),
                params.get('process_name', 'unknown'),
                incident_id
            ),
            'quarantine_file': lambda: self.quarantine_file(params.get('filepath', ''), incident_id),
            'isolate_host': lambda: self.isolate_host(params.get('hostname', 'localhost'), incident_id),
            'disable_user_account': lambda: self.disable_user_account(params.get('username', ''), incident_id),
        }
        
        if action_type in action_map:
            return action_map[action_type]()
        else:
            return {
                'action': action_type,
                'status': 'failed',
                'reason': f'Unknown action type: {action_type}',
                'timestamp': datetime.utcnow().isoformat()
            }
    
    def _is_valid_ip(self, ip: str) -> bool:
        """Validate IP address format"""
        pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if not re.match(pattern, ip):
            return False
        
        # Check each octet is 0-255
        octets = ip.split('.')
        return all(0 <= int(octet) <= 255 for octet in octets)


if __name__ == '__main__':
    # Test containment engine
    engine = ContainmentEngine(mode='simulate')
    
    # Test IP blocking
    result = engine.block_ip('192.168.1.100', incident_id=1)
    print("Block IP Result:")
    print(json.dumps(result, indent=2))
    print()
    
    # Test recommendations
    message = "Failed password for admin from 192.168.1.100"
    recommendations = engine.recommend_actions('failed_login', message)
    print("Recommendations:")
    print(json.dumps(recommendations, indent=2))
    print()
    
    # Test action execution
    action_result = engine.execute_action('block_ip', {'ip_address': '10.0.0.50'}, incident_id=2)
    print("Execute Action Result:")
    print(json.dumps(action_result, indent=2))
