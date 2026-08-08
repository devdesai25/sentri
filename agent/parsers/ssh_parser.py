import re
import time
from datetime import datetime, timedelta
from typing import Dict, Any, Optional

from .base import BaseParser

class SSHParser(BaseParser):
    """Parser for SSH log entries with expanded pattern support for various formats"""
    
    # Enhanced regular expressions for different SSH log formats
    PATTERNS = {
        'accepted': [
            # Modern format with ISO timestamp and hostname (AWS/systemd)
            re.compile(
                r'(?P<time>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d+[+-]\d{2}:\d{2})\s+'
                r'(?P<hostname>\S+)\s+sshd\[\d+\]:\s+'
                r'Accepted (?P<auth_method>\S+) for (?P<user>\S+) from '
                r'(?P<ip_address>\S+)'
            ),
            # Traditional syslog format
            re.compile(
                r'(?P<time>\w{3}\s+\d+\s+\d+:\d+:\d+).*sshd\[\d+\]:\s+'
                r'Accepted (?P<auth_method>\S+) for (?P<user>\S+) from '
                r'(?P<ip_address>\S+)'
            ),
            # Session opened format
            re.compile(
                r'(?P<time>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d+[+-]\d{2}:\d{2})\s+'
                r'(?P<hostname>\S+)\s+sshd\[\d+\]:\s+'
                r'(?:session opened|New session) .*? for user (?P<user>\S+)'
            ),
        ],
        'pam_session': [
            # PAM session opening (common in Ubuntu/RHEL)
            re.compile(
                r'(?P<time>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d+[+-]\d{2}:\d{2})\s+'
                r'(?P<hostname>\S+)\s+sshd\[\d+\]:\s+'
                r'pam_unix\(sshd:session\): session opened for user (?P<user>[^\s\(]+)(?:\(uid=\d+\))? by'
            ),
            # Traditional format
            re.compile(
                r'(?P<time>\w{3}\s+\d+\s+\d+:\d+:\d+).*sshd\[\d+\]:\s+'
                r'pam_unix\(sshd:session\): session opened for user (?P<user>[^\s\(]+)'
            ),
        ],
        'systemd_session': [
            # Systemd-logind new session
            re.compile(
                r'(?P<time>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d+[+-]\d{2}:\d{2})\s+'
                r'(?P<hostname>\S+)\s+systemd-logind\[\d+\]:\s+'
                r'New session (?P<session_id>\d+) of user (?P<user>\S+)'
            ),
        ],
        'failed': [
            # Modern format
            re.compile(
                r'(?P<time>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d+[+-]\d{2}:\d{2})\s+'
                r'(?P<hostname>\S+)\s+sshd\[\d+\]:\s+'
                r'Failed (?P<auth_method>\S+) for (?P<user>\S+) from '
                r'(?P<ip_address>\S+)'
            ),
            # Traditional format
            re.compile(
                r'(?P<time>\w{3}\s+\d+\s+\d+:\d+:\d+).*sshd\[\d+\]:\s+'
                r'Failed (?P<auth_method>\S+) for (?P<user>\S+) from '
                r'(?P<ip_address>\S+)'
            ),
            # Modern authentication failure format
            re.compile(
                r'(?P<time>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d+[+-]\d{2}:\d{2})\s+'
                r'(?P<hostname>\S+)\s+sshd\[\d+\]:\s+'
                r'pam_unix\(sshd:auth\): authentication failure.*rhost=(?P<ip_address>\S+).*user=(?P<user>\S+)'
            ),
        ],
        'invalid_user': [
            # Modern format
            re.compile(
                r'(?P<time>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d+[+-]\d{2}:\d{2})\s+'
                r'(?P<hostname>\S+)\s+sshd\[\d+\]:\s+'
                r'Invalid user (?P<user>\S+) from (?P<ip_address>\S+)'
            ),
            # Traditional format
            re.compile(
                r'(?P<time>\w{3}\s+\d+\s+\d+:\d+:\d+).*sshd\[\d+\]:\s+'
                r'Invalid user (?P<user>\S+) from (?P<ip_address>\S+)'
            ),
        ],
        'connection_closed': [
            # Modern format
            re.compile(
                r'(?P<time>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d+[+-]\d{2}:\d{2})\s+'
                r'(?P<hostname>\S+)\s+sshd\[\d+\]:\s+'
                r'(?:Connection closed|Disconnected from) (?:user (?P<user>\S+) )?(?P<ip_address>\S+)'
            ),
            # Traditional format
            re.compile(
                r'(?P<time>\w{3}\s+\d+\s+\d+:\d+:\d+).*sshd\[\d+\]:\s+'
                r'(?:Connection closed|Disconnected from) (?:user (?P<user>\S+) )?(?P<ip_address>\S+)'
            ),
        ]
    }
    
    # Configuration for event deduplication and correlation
    DEDUP_TIMEOUT = 5  # seconds to consider events as duplicates
    
    def __init__(self, debug=False):
        super().__init__()
        self.debug = debug
        # Store recent login events by user to avoid duplicates
        # Structure: user -> {'timestamp': time, 'event': event_data, 'reported': bool}
        self._recent_logins = {}
        # Store process IDs seen in logs to help with correlation
        # Structure: pid -> {'user': user, 'ip': ip, 'method': method}
        self._pid_info = {}
        # Store track of already reported users in the current session
        self._reported_users = set()
        
    def parse(self, log_line: str, metadata: Dict[str, Any] = None) -> Optional[Dict[str, Any]]:
        """
        Parse an SSH log line into a structured event.
        
        Args:
            log_line: The log line to parse
            metadata: Additional metadata about the log line
            
        Returns:
            A structured event dict if the line matches an SSH event pattern,
            None otherwise.
        """
        if self.debug:
            print(f"DEBUG: Parsing line: {log_line}")
            
        if metadata is None:
            metadata = {}
            
        # Extract process ID from the log line if present
        pid_match = re.search(r'\[\s*(\d+)\]', log_line)
        current_pid = pid_match.group(1) if pid_match else None
        
        # Try each event type and its patterns
        for event_type, patterns in self.PATTERNS.items():
            for pattern in patterns:
                match = pattern.search(log_line)  # Using search instead of match
                if match:
                    if self.debug:
                        print(f"DEBUG: Matched pattern for {event_type}")
                    
                    event_data = match.groupdict()
                    user = (event_data.get('user') or 'unknown').strip('.')  # Remove trailing dots sometimes present
                    
                    # Store timestamp
                    current_time = time.time()
                    
                    # Handle different event types
                    if event_type == 'accepted':
                        # This is a primary SSH login event
                        # Store complete information about this login
                        ip_address = event_data.get('ip_address', 'unknown')
                        auth_method = event_data.get('auth_method', 'unknown')
                        
                        # If we have the PID, store this information for correlation
                        if current_pid:
                            self._pid_info[current_pid] = {
                                'user': user,
                                'ip': ip_address,
                                'method': auth_method
                            }
                        
                        # Create the event with complete information
                        login_event = {
                            'event': 'ssh_login_success',
                            'user': user,
                            'ip_address': ip_address,
                            'auth_method': auth_method,
                            'timestamp': self._parse_timestamp(event_data.get('time')),
                            'source': metadata.get('source', 'unknown')
                        }
                        
                        # Check if this is a duplicate login event
                        if self._is_duplicate_login(user, current_time):
                            if self.debug:
                                print(f"DEBUG: Suppressing duplicate login for user {user}")
                            return None
                        
                        # Store this login and mark as reported
                        self._recent_logins[user] = {
                            'timestamp': current_time,
                            'event': login_event,
                            'reported': True
                        }
                        self._reported_users.add(user)
                        
                        return login_event
                    
                    elif event_type in ('pam_session', 'systemd_session'):
                        # These are secondary events related to a login
                        # Check if we've already seen a primary event for this user
                        if self._is_duplicate_login(user, current_time):
                            if self.debug:
                                print(f"DEBUG: Skipping secondary event for recently logged in user {user}")
                            return None
                        
                        # If this is from systemd-logind and we haven't reported it yet
                        if event_type == 'systemd_session' and user not in self._reported_users:
                            # Try to find correlating information from previous PID records
                            ip_address = 'unknown'
                            auth_method = 'unknown'
                            
                            # Create a more limited login event
                            login_event = {
                                'event': 'ssh_login_success',
                                'user': user,
                                'ip_address': ip_address,
                                'auth_method': auth_method,
                                'timestamp': self._parse_timestamp(event_data.get('time')),
                                'source': metadata.get('source', 'unknown')
                            }
                            
                            # Store this login and mark as reported
                            self._recent_logins[user] = {
                                'timestamp': current_time,
                                'event': login_event,
                                'reported': True
                            }
                            self._reported_users.add(user)
                            
                            # We'll only report this if we don't have better information
                            # from a primary event
                            return None
                            
                        # Otherwise, we don't need to report these secondary events
                        return None
                        
                    elif event_type == 'failed':
                        # Failed login attempts
                        return {
                            'event': 'ssh_login_failed',
                            'user': user,
                            'ip_address': event_data.get('ip_address', 'unknown'),
                            'auth_method': event_data.get('auth_method', 'unknown'),
                            'timestamp': self._parse_timestamp(event_data.get('time')),
                            'source': metadata.get('source', 'unknown')
                        }
                        
                    elif event_type == 'invalid_user':
                        return {
                            'event': 'ssh_invalid_user',
                            'user': user,
                            'ip_address': event_data.get('ip_address', 'unknown'),
                            'timestamp': self._parse_timestamp(event_data.get('time')),
                            'source': metadata.get('source', 'unknown')
                        }
                        
                    elif event_type == 'connection_closed':
                        return {
                            'event': 'ssh_connection_closed',
                            'user': user if user != 'unknown' else None,
                            'ip_address': event_data.get('ip_address', 'unknown'),
                            'timestamp': self._parse_timestamp(event_data.get('time')),
                            'source': metadata.get('source', 'unknown')
                        }
                        
        # If we get here, no pattern matched
        if self.debug and ('sshd' in log_line or 'ssh' in log_line):
            print(f"DEBUG: No pattern matched for SSH-related line: {log_line}")
            
        return None
        
    def _is_duplicate_login(self, user: str, current_time: float) -> bool:
        """Check if we've seen a login for this user recently"""
        if user in self._recent_logins:
            login_data = self._recent_logins[user]
            # Check if it's within our deduplication window
            if current_time - login_data['timestamp'] < self.DEDUP_TIMEOUT:
                return True
        return False
        
    def _parse_timestamp(self, time_str: Optional[str]) -> Optional[datetime]:
        """Parse a timestamp string into a datetime object"""
        if not time_str:
            return None
            
        try:
            # Try ISO format first
            if 'T' in time_str:
                # Handle ISO 8601 timestamp
                # Strip microseconds and timezone for simpler parsing
                iso_time = time_str.split('.')[0]
                return datetime.fromisoformat(iso_time)
            else:
                # Handle traditional syslog format
                current_year = datetime.now().year
                timestamp = f"{time_str} {current_year}"
                return datetime.strptime(timestamp, '%b %d %H:%M:%S %Y')
        except (ValueError, TypeError):
            # Keep the original string if parsing fails
            if self.debug:
                print(f"DEBUG: Failed to parse timestamp: {time_str}")
            return None

    def cleanup_old_events(self):
        """Clean up old events to prevent memory leaks"""
        current_time = time.time()
        # Clean up logins older than 10x our dedup timeout
        cutoff = current_time - (self.DEDUP_TIMEOUT * 10)
        
        # Remove old login events
        old_users = []
        for user, data in self._recent_logins.items():
            if data['timestamp'] < cutoff:
                old_users.append(user)
                
        for user in old_users:
            del self._recent_logins[user]
            if user in self._reported_users:
                self._reported_users.remove(user)
                
        # Periodically reset our PID tracking to avoid memory leaks
        if len(self._pid_info) > 1000:  # Arbitrary limit
            self._pid_info = {}