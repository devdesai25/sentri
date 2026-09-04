import re
import time
from datetime import datetime
from typing import Dict, Any, Optional, List

from .base import BaseParser
import asyncio
from agent.api.client import ApiClient  # Import our new API client


class AuditdCommandParser(BaseParser):
    """Parser for auditd log entries related to command execution."""
    
    def __init__(self, debug=False, api_client=None):
        self.debug = debug
        self.api_client = api_client
        # Track partial command events by ID
        self.partial_events = {}
        # Event cleanup timer
        self.last_cleanup = time.time()
        # Track recently reported commands to avoid duplicates
        self.recent_commands = {}
        
        # Patterns for matching different auditd record types
        self.msg_pattern = re.compile(r'msg=audit\((?P<timestamp>[\d\.]+):(?P<event_id>\d+)\)')
        self.syscall_pattern = re.compile(r'type=SYSCALL .*? syscall=(?P<syscall>\d+) success=(?P<success>\S+) .*? ppid=(?P<ppid>\d+) pid=(?P<pid>\d+) auid=(?P<auid>\d+) uid=(?P<uid>\d+) gid=(?P<gid>\d+)')
        self.uid_info_pattern = re.compile(r'AUID="(?P<auid_name>[^"]+)" UID="(?P<uid_name>[^"]+)" GID="(?P<gid_name>[^"]+)"')
        self.execve_pattern = re.compile(r'type=EXECVE .*? argc=(?P<argc>\d+)(?: a0="(?P<a0>[^"]+)")?(?: a1="(?P<a1>[^"]+)")?(?: a2="(?P<a2>[^"]+)")?')
        self.cwd_pattern = re.compile(r'type=CWD .*? cwd="(?P<cwd>[^"]+)"')
        self.path_pattern = re.compile(r'type=PATH .*? item=0 name="(?P<name>[^"]+)"')
        self.proctitle_pattern = re.compile(r'type=PROCTITLE .*? proctitle=(?P<proctitle>[0-9A-F]+)')
        
        # Syscall number for execve (could be different on some architectures)
        self.execve_syscall = 59  # execve syscall number on x86_64
        
        # Command deduplication window (seconds)
        self.dedup_window = 5
        
    def parse(self, log_line: str, metadata: Dict[str, Any] = None) -> Optional[Dict[str, Any]]:
        """
        Parse a log line into a structured event.
        
        Args:
            log_line: The log line to parse
            metadata: Additional metadata about the log line
            
        Returns:
            A structured event dict if the parsing succeeded, None otherwise.
        """
        if metadata is None:
            metadata = {}
            
        # Check if it's time to clean up old events
        current_time = time.time()
        if current_time - self.last_cleanup > 60:  # Clean up every minute
            self._cleanup_old_events()
            self.last_cleanup = current_time
        
        # Skip lines that don't look like audit logs
        if not log_line.startswith('type='):
            return None
            
        # Extract event ID and timestamp
        msg_match = self.msg_pattern.search(log_line)
        if not msg_match:
            return None
            
        timestamp = float(msg_match.group('timestamp'))
        event_id = msg_match.group('event_id')
        
        # Initialize event if not already present
        if event_id not in self.partial_events:
            self.partial_events[event_id] = {
                'timestamp': datetime.fromtimestamp(timestamp).isoformat(),
                'event_id': event_id,
                'parts': set(),
                'created_at': current_time
            }
        
        # Track which parts we've seen
        event = self.partial_events[event_id]
        
        # Process SYSCALL records
        syscall_match = self.syscall_pattern.search(log_line)
        if syscall_match:
            event['parts'].add('syscall')
            syscall = int(syscall_match.group('syscall'))
            
            # Check UID info if available
            uid_info_match = self.uid_info_pattern.search(log_line)
            if uid_info_match:
                event['auid_name'] = uid_info_match.group('auid_name')
                event['uid_name'] = uid_info_match.group('uid_name')
                event['gid_name'] = uid_info_match.group('gid_name')
            
            if syscall != self.execve_syscall:
                # We're only interested in execve syscalls
                del self.partial_events[event_id]
                return None
                
            # This is an execve syscall, so gather relevant information
            event['success'] = syscall_match.group('success') == 'yes'
            event['uid'] = syscall_match.group('uid')
            event['auid'] = syscall_match.group('auid')
            event['gid'] = syscall_match.group('gid')
            event['pid'] = syscall_match.group('pid')
            event['ppid'] = syscall_match.group('ppid')
            
        # Process EXECVE records
        execve_match = self.execve_pattern.search(log_line)
        if execve_match:
            event['parts'].add('execve')
            
            argc = int(execve_match.group('argc'))
            args = []
            
            # Get the command (a0)
            command = execve_match.group('a0')
            if command:
                event['command'] = command
                
            # Extract arguments from a1 to an
            for i in range(1, argc):
                arg_match = re.search(f' a{i}="([^"]+)"', log_line)
                if arg_match:
                    args.append(arg_match.group(1))
            
            event['args'] = args
                
        # Process CWD records
        cwd_match = self.cwd_pattern.search(log_line)
        if cwd_match:
            event['parts'].add('cwd')
            event['cwd'] = cwd_match.group('cwd')
            
        # Process PATH records for the executable path
        path_match = self.path_pattern.search(log_line)
        if path_match:
            event['parts'].add('path')
            event['executable'] = path_match.group('name')
            
        # Process PROCTITLE records (contains hex-encoded command line)
        proctitle_match = self.proctitle_pattern.search(log_line)
        if proctitle_match:
            event['parts'].add('proctitle')
            hex_title = proctitle_match.group('proctitle')
            try:
                # Try to decode the hex string to get the full command line
                proctitle_bytes = bytes.fromhex(hex_title)
                proctitle = proctitle_bytes.decode('utf-8', errors='replace')
                event['proctitle'] = proctitle
            except Exception as e:
                if self.debug:
                    print(f"DEBUG: Failed to decode proctitle: {e}")
            
        # Check if we have enough information to create a complete command event
        # At minimum, we need syscall, execve and either command or executable
        if {'syscall', 'execve'}.issubset(event['parts']) and event.get('success', False):
            if 'command' in event or 'executable' in event:
                # Get username - prefer the name from UID info if available
                username = event.get('uid_name', self._get_username_from_uid(event.get('uid', '0')))
                
                # System/internal command filtering
                # Do not emit events for commands run by root (uid 0) or known system daemons
                system_users = {'root', 'systemd', 'daemon', 'syslog', 'messagebus', 'nobody'}
                system_commands = {'systemd', 'init', 'cron', 'rsyslogd', 'auditd', 'dbus-daemon', 'agetty', 'login', 'sshd', 'bash', 'sh'}
                if (
                    username in system_users or
                    event.get('uid', '') == '0' or
                    event.get('command', '') in system_commands or
                    event.get('executable', '') in system_commands or
                    event.get('comm', '') in system_commands
                ):
                    if self.debug:
                        print(f"DEBUG: Skipping system/internal command: {username} {event.get('command', '')}")
                    del self.partial_events[event_id]
                    return None
                
                # Create a command event
                command_str = event.get('command', event.get('executable', 'unknown'))
                args_str = ' '.join(event.get('args', []))
                
                # Check for duplication
                command_key = f"{username}:{command_str}:{args_str}"
                if self._is_duplicate_command(command_key, current_time):
                    # Clean up and skip this duplicate
                    if self.debug:
                        print(f"DEBUG: Skipping duplicate command: {command_key}")
                    del self.partial_events[event_id]
                    return None
                
                # Mark this command as seen
                self.recent_commands[command_key] = current_time
                
                # Build the complete event
                command_event = {
                    'event': 'command_execution',
                    'timestamp': event['timestamp'],
                    'user': username,
                    'command': command_str,
                    'arguments': args_str,
                    'working_directory': event.get('cwd', ''),
                    'pid': event.get('pid', ''),
                    'source': metadata.get('source', 'auditd'),
                    'metadata': {
                        'uid': event.get('uid', ''),
                        'auid': event.get('auid', ''),
                        'gid': event.get('gid', ''),
                        'ppid': event.get('ppid', '')
                    }
                }
                
                # If we have an API client, assess the risk
                if self.api_client:
                    try:
                        # Create a future for the API call to avoid blocking
                        loop = asyncio.get_event_loop()
                        risk_future = asyncio.run_coroutine_threadsafe(
                            self.api_client.assess_command_risk(command_event),
                            loop
                        )
                        
                        # Wait for result with a timeout
                        risk_assessment = risk_future.result(timeout=5)
                        
                        if risk_assessment:
                            # Add risk data to the command event
                            command_event['risk_level'] = risk_assessment.get('risk_level', 'unknown')
                            command_event['risk_reason'] = risk_assessment.get('reason', '')
                            
                            if self.debug:
                                print(f"DEBUG: Command risk assessed as {command_event['risk_level']}")
                    except (asyncio.TimeoutError, asyncio.CancelledError):
                        if self.debug:
                            print("DEBUG: Risk assessment timed out")
                    except Exception as e:
                        if self.debug:
                            print(f"DEBUG: Error in risk assessment: {str(e)}")
                
                # Clean up the partial event
                del self.partial_events[event_id]
                
                # return command_event
                
                return command_event
                
        # If we get here, the event is not yet complete
        return None
        
    def _get_username_from_uid(self, uid):
        """Get username from UID."""
        # In a real implementation, we would use:
        # import pwd
        # try:
        #     return pwd.getpwuid(int(uid)).pw_name
        # except (KeyError, ValueError):
        #     return f"user_{uid}"
        return f"user_{uid}"
        
    def _is_duplicate_command(self, command_key, current_time):
        """Check if this command was recently seen."""
        if command_key in self.recent_commands:
            if current_time - self.recent_commands[command_key] < self.dedup_window:
                return True
        return False
        
    def _cleanup_old_events(self):
        """Clean up old partial events and recent commands."""
        current_time = time.time()
        
        # Clean up partial events older than 30 seconds
        event_ids_to_remove = []
        for event_id, event in self.partial_events.items():
            if current_time - event.get('created_at', 0) > 30:
                event_ids_to_remove.append(event_id)
        
        for event_id in event_ids_to_remove:
            del self.partial_events[event_id]
            
        # Clean up old command records
        commands_to_remove = []
        for command_key, timestamp in self.recent_commands.items():
            if current_time - timestamp > 300:  # 5 minutes
                commands_to_remove.append(command_key)
                
        for command_key in commands_to_remove:
            del self.recent_commands[command_key]
            
    def cleanup_old_events(self):
        """Clean up old events - Called periodically by the agent"""
        self._cleanup_old_events()