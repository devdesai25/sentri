import re
import time
import subprocess
import threading
import os
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List, Tuple
import logging

from .base import BaseParser

logger = logging.getLogger('sentri.privilege')

class AccountLockoutManager:
    """Manages account lockouts and scheduled unlocks."""
    
    def __init__(self, debug=False):
        self.debug = debug
        self.locked_users = {}  # username -> unlock_time
        self.lock_timers = {}   # username -> timer_thread
        
    def lock_account(self, username: str, minutes: int) -> Tuple[bool, str]:
        """
        Lock a user account for the specified number of minutes.
        
        Args:
            username: Username to lock
            minutes: Minutes to lock the account for
            
        Returns:
            Tuple of (success, message)
        """
        if self.debug:
            logger.debug(f"Attempting to lock account for user {username} for {minutes} minutes")
            
        # Check if we have root privileges
        if os.geteuid() != 0:
            return False, "Account lockout requires root privileges"
            
        # Check if user exists
        try:
            subprocess.run(['id', username], check=True, capture_output=True)
        except subprocess.CalledProcessError:
            return False, f"User {username} does not exist"
            
        # Check if user is already locked
        if username in self.locked_users:
            return False, f"User {username} is already locked"
            
        # Lock the account using usermod
        try:
            subprocess.run(['usermod', '-L', username], check=True)
            
            # Calculate unlock time
            unlock_time = time.time() + (minutes * 60)
            self.locked_users[username] = unlock_time
            
            # Schedule unlock
            self._schedule_unlock(username, minutes)
            
            if self.debug:
                logger.debug(f"Account locked for user {username} until {datetime.fromtimestamp(unlock_time)}")
                
            return True, f"Account locked for {minutes} minutes"
            
        except subprocess.CalledProcessError as e:
            error_msg = f"Failed to lock account: {str(e)}"
            logger.error(error_msg)
            return False, error_msg
    
    def unlock_account(self, username: str) -> Tuple[bool, str]:
        """
        Unlock a user account.
        
        Args:
            username: Username to unlock
            
        Returns:
            Tuple of (success, message)
        """
        if self.debug:
            logger.debug(f"Attempting to unlock account for user {username}")
            
        # Check if we have root privileges
        if os.geteuid() != 0:
            return False, "Account unlock requires root privileges"
            
        # Unlock the account using usermod
        try:
            subprocess.run(['usermod', '-U', username], check=True)
            
            # Remove from locked users
            if username in self.locked_users:
                del self.locked_users[username]
                
            # Cancel timer if it exists
            if username in self.lock_timers:
                timer = self.lock_timers.pop(username)
                timer.cancel()
                
            if self.debug:
                logger.debug(f"Account unlocked for user {username}")
                
            return True, "Account unlocked"
            
        except subprocess.CalledProcessError as e:
            error_msg = f"Failed to unlock account: {str(e)}"
            logger.error(error_msg)
            return False, error_msg
    
    def terminate_user_sessions(self, username: str) -> Tuple[bool, str]:
        """
        Terminate all sessions for a user.
        
        Args:
            username: Username whose sessions to terminate
            
        Returns:
            Tuple of (success, message)
        """
        if self.debug:
            logger.debug(f"Attempting to terminate sessions for user {username}")
            
        # Check if we have root privileges
        if os.geteuid() != 0:
            return False, "Session termination requires root privileges"
            
        # Check if user exists
        try:
            subprocess.run(['id', username], check=True, capture_output=True)
        except subprocess.CalledProcessError:
            return False, f"User {username} does not exist"
            
        # Terminate user sessions using pkill
        try:
            # Use pkill to kill all processes owned by the user
            result = subprocess.run(['pkill', '-KILL', '-u', username], capture_output=True)
            
            # pkill returns 0 if any process was killed, 1 if no processes were matched
            if result.returncode > 1:  # An error occurred
                return False, f"Error terminating sessions: {result.stderr.decode()}"
                
            if self.debug:
                if result.returncode == 0:
                    logger.debug(f"Sessions terminated for user {username}")
                else:
                    logger.debug(f"No active sessions found for user {username}")
                
            return True, "Sessions terminated"
            
        except Exception as e:
            error_msg = f"Failed to terminate sessions: {str(e)}"
            logger.error(error_msg)
            return False, error_msg
    
    def is_account_locked(self, username: str) -> bool:
        """
        Check if an account is currently locked.
        
        Args:
            username: Username to check
            
        Returns:
            True if the account is locked, False otherwise
        """
        return username in self.locked_users
    
    def get_remaining_lockout_time(self, username: str) -> int:
        """
        Get the remaining lockout time in minutes.
        
        Args:
            username: Username to check
            
        Returns:
            Remaining minutes or 0 if not locked
        """
        if username not in self.locked_users:
            return 0
            
        remaining_seconds = max(0, self.locked_users[username] - time.time())
        return int(remaining_seconds / 60)
    
    def _schedule_unlock(self, username: str, minutes: int) -> None:
        """
        Schedule account unlock after specified minutes.
        
        Args:
            username: Username to unlock
            minutes: Minutes to wait before unlocking
        """
        # Create a timer
        timer = threading.Timer(minutes * 60, self._unlock_timer_callback, args=[username])
        timer.daemon = True  # Make sure the timer doesn't prevent program exit
        
        # Save the timer and start it
        self.lock_timers[username] = timer
        timer.start()
        
        if self.debug:
            logger.debug(f"Scheduled unlock for {username} in {minutes} minutes")
    
    def _unlock_timer_callback(self, username: str) -> None:
        """
        Callback function for unlock timer.
        
        Args:
            username: Username to unlock
        """
        success, message = self.unlock_account(username)
        
        if self.debug:
            if success:
                logger.debug(f"Auto-unlock for {username}: {message}")
            else:
                logger.debug(f"Auto-unlock failed for {username}: {message}")
                
        # Remove the timer from the dictionary
        if username in self.lock_timers:
            del self.lock_timers[username]


class PrivilegeEscalationParser(BaseParser):
    """Parser for privilege escalation events from auth logs."""
    
    # Default configuration
    DEFAULT_FAILURE_THRESHOLD = 3       # Max allowed failures before alerting
    DEFAULT_FAILURE_WINDOW = 30 * 60    # 30 minutes in seconds
    DEFAULT_LOCKOUT_MINUTES = 15        # Default lockout duration in minutes
    DEFAULT_ENABLE_LOCKOUT = False      # Account lockout disabled by default
    DEFAULT_ENABLE_TERMINATION = False  # Session termination disabled by default
    
    def __init__(self, debug=False, 
                failure_threshold=None, 
                failure_window_minutes=None,
                enable_lockout=None,
                lockout_minutes=None,
                enable_termination=None):
        super().__init__()
        self.debug = debug
        
        # Configure failure tracking
        self.failure_threshold = failure_threshold or self.DEFAULT_FAILURE_THRESHOLD
        self.failure_window = (failure_window_minutes or 30) * 60  # Convert minutes to seconds
        
        # Configure lockout settings
        self.enable_lockout = enable_lockout if enable_lockout is not None else self.DEFAULT_ENABLE_LOCKOUT
        self.lockout_minutes = lockout_minutes or self.DEFAULT_LOCKOUT_MINUTES
        self.enable_termination = enable_termination if enable_termination is not None else self.DEFAULT_ENABLE_TERMINATION
        
        # Create lockout manager
        self.lockout_manager = AccountLockoutManager(debug=debug)
        
        if debug:
            logger.setLevel(logging.DEBUG)
            
        # Regular expressions based on actual log format samples
        self.PATTERNS = [
            # Sudo authentication failure pattern
            ('sudo_auth_failure', re.compile(
                r'(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d+[+-]\d{2}:\d{2})\s+'
                r'(?P<hostname>\S+)\s+sudo:.*authentication failure.*user=(?P<user>\S+)'
            )),
            # Sudo execution pattern
            ('sudo_exec', re.compile(
                r'(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d+[+-]\d{2}:\d{2})\s+'
                r'(?P<hostname>\S+)\s+sudo(?:\[\d+\])?:\s+(?P<user>\S+)\s+:\s+.*COMMAND=(?P<command>.*)'
            )),
            # Su session opened pattern - indicates a successful attempt
            ('su_session_opened', re.compile(
                r'(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d+[+-]\d{2}:\d{2})\s+'
                r'(?P<hostname>\S+)\s+su\[\d+\]:\s+pam_unix\(su:session\):\s+session\s+'
                r'opened for user\s+(?P<target_user>[^\(]+)(?:\(uid=\d+\))?\s+by\s+(?P<user>[^\(]+)'
            )),
            # Su authentication failure pattern 
            ('su_authentication_failure', re.compile(
                r'(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d+[+-]\d{2}:\d{2})\s+'
                r'(?P<hostname>\S+)\s+su:\s+pam_unix\(su:auth\):\s+authentication failure;'
                r'.*ruser=(?P<user>\S+).*user=(?P<target_user>\S+)'
            ))
        ]
        
        # Track recent events for deduplication
        self.recent_events = {}
        self.dedup_window = 5  # seconds
        
        # Track authentication failures
        self.auth_failures = {}  # Format: {username: [timestamp1, timestamp2, ...]}
        
        # Track users who have been locked out
        self.locked_out_users = {}  # Format: {username: locked_until_timestamp}
        
    def parse(self, log_line: str, metadata: Dict[str, Any] = None) -> Optional[Dict[str, Any]]:
        """
        Parse a log line into a structured privilege escalation event.
        
        Args:
            log_line: The log line to parse
            metadata: Additional metadata about the log line
            
        Returns:
            Dict containing the parsed event or None if line doesn't match
        """
        if metadata is None:
            metadata = {}
            
        # Quick pre-check to skip irrelevant lines
        if not ('su[' in log_line or 'su:' in log_line or 'sudo' in log_line):
            return None
            
        # For debugging
        if self.debug:
            logger.debug(f"Checking privilege escalation line: {log_line}")
            
        # Try each pattern
        for event_type, pattern in self.PATTERNS:
            match = pattern.search(log_line)
            if match:
                if self.debug:
                    logger.debug(f"Matched privilege escalation pattern for {event_type}")
                
                # Extract matched data
                event_data = match.groupdict()
                
                # Create the base event
                event = {
                    'event': 'privilege_escalation',
                    'subtype': event_type,
                    'timestamp': event_data.get('timestamp'),
                    'source': metadata.get('source', 'unknown'),
                    'original_log': log_line  # Store original log for debugging
                }
                
                # Add fields based on the event type
                if event_type == 'su_authentication_failure':
                    event['user'] = event_data.get('user', '').strip('()')
                    event['target_user'] = event_data.get('target_user', '').strip('()')
                    event['success'] = False
                    event['description'] = f"User '{event['user']}' failed to switch to '{event['target_user']}'"
                    
                    # Track this failure
                    user_locked_out = self._record_auth_failure(event['user'])
                    event['user_locked_out'] = user_locked_out
                    
                elif event_type == 'su_session_opened':
                    event['user'] = event_data.get('user', '').strip('()')
                    event['target_user'] = event_data.get('target_user', '').strip('()')
                    event['success'] = True
                    event['description'] = f"User '{event['user']}' successfully switched to '{event['target_user']}'"
                    
                elif event_type == 'sudo_auth_failure':
                    event['user'] = event_data.get('user', '')
                    event['success'] = False
                    event['description'] = f"User '{event['user']}' failed sudo authentication"
                    
                    # Track this failure
                    user_locked_out = self._record_auth_failure(event['user'])
                    event['user_locked_out'] = user_locked_out
                    
                elif event_type == 'sudo_exec':
                    event['user'] = event_data.get('user', '')
                    event['command'] = event_data.get('command', '')
                    event['success'] = True
                    event['description'] = f"User '{event['user']}' executed command with sudo: {event['command']}"
                
                # Check for duplicate events by their keys
                event_key = self._create_event_key(event)
                if self._is_duplicate_event(event_key):
                    if self.debug:
                        logger.debug(f"Suppressing duplicate privilege escalation event: {event_key}")
                    return None
                
                # Save event key to recent events
                self.recent_events[event_key] = time.time()
                
                # Check if we need to alert for excessive failures
                if not event.get('success', True):
                    user = event.get('user', '')
                    failure_count = self._get_recent_failure_count(user)
                    if failure_count >= self.failure_threshold:
                        event['threshold_exceeded'] = True
                        event['failure_count'] = failure_count
                        event['description'] += f" [ALERT: {failure_count} failed attempts in the last {self.failure_window // 60} minutes]"
                        
                        # Get lockout info if applicable
                        if event.get('user_locked_out', False):
                            remaining_time = self.lockout_manager.get_remaining_lockout_time(user)
                            if remaining_time > 0:
                                event['description'] += f" [USER LOCKED: {remaining_time} minutes remaining]"
                
                if self.debug:
                    logger.debug(f"Created privilege escalation event: {event}")
                
                return event
                
        return None
    
    def _record_auth_failure(self, username: str) -> bool:
        """
        Record an authentication failure for a user and lock if needed.
        
        Args:
            username: The username to record the failure for
            
        Returns:
            True if the user was locked out, False otherwise
        """
        current_time = time.time()
        
        # Skip certain usernames
        if username in ['root', 'nobody', '']:
            if self.debug:
                logger.debug(f"Skipping auth failure tracking for special user: {username}")
            return False
        
        # Initialize list for this user if needed
        if username not in self.auth_failures:
            self.auth_failures[username] = []
            
        # Add the current timestamp to the user's failures
        self.auth_failures[username].append(current_time)
        
        # Clean up old failures for this user
        self._cleanup_old_failures(username)
        
        # Check if account is already locked
        if self.lockout_manager.is_account_locked(username):
            return True
            
        # Log the failure count for debugging
        failure_count = len(self.auth_failures[username])
        if self.debug:
            logger.debug(f"Recorded auth failure for {username} (count: {failure_count})")
            
        # Check if we need to lock the account
        if failure_count >= self.failure_threshold:
            if self.debug:
                logger.debug(f"User {username} has exceeded the failure threshold ({self.failure_threshold})")
                
            # Lock the account if enabled
            if self.enable_lockout:
                # Terminate sessions if enabled
                if self.enable_termination:
                    success, message = self.lockout_manager.terminate_user_sessions(username)
                    if self.debug:
                        logger.debug(f"Session termination for {username}: {message}")
                
                # Lock the account
                success, message = self.lockout_manager.lock_account(username, self.lockout_minutes)
                if self.debug:
                    logger.debug(f"Account lockout for {username}: {message}")
                
                return success
                
        return False
    
    def _get_recent_failure_count(self, username: str) -> int:
        """
        Get the number of recent failures for a user within the failure window.
        
        Args:
            username: The username to check
            
        Returns:
            The number of failures within the window
        """
        if username not in self.auth_failures:
            return 0
            
        # Clean up old failures first
        self._cleanup_old_failures(username)
        
        # Return the count of remaining failures
        return len(self.auth_failures[username])
    
    def _cleanup_old_failures(self, username: str) -> None:
        """
        Remove old failures outside the failure window.
        
        Args:
            username: The username to clean up failures for
        """
        if username not in self.auth_failures:
            return
            
        current_time = time.time()
        cutoff_time = current_time - self.failure_window
        
        # Keep only failures within the window
        self.auth_failures[username] = [
            timestamp for timestamp in self.auth_failures[username]
            if timestamp >= cutoff_time
        ]
        
    def _create_event_key(self, event: Dict[str, Any]) -> str:
        """Create a unique key for deduplication based on event data."""
        subtype = event.get('subtype', '')
        user = event.get('user', '')
        target_user = event.get('target_user', '')
        timestamp = event.get('timestamp', '')[:19]  # Use just the main part of timestamp
        
        return f"{timestamp}:{subtype}:{user}:{target_user}"
    
    def _is_duplicate_event(self, event_key: str) -> bool:
        """Check if we've seen this event recently."""
        if event_key in self.recent_events:
            # Check if it's within our deduplication window
            if time.time() - self.recent_events[event_key] < self.dedup_window:
                return True
        return False
    
    def cleanup_old_events(self):
        """Clean up old events to prevent memory leaks."""
        current_time = time.time()
        # Remove events older than 5x our dedup window
        cutoff = current_time - (self.dedup_window * 5)
        
        # Remove old events
        keys_to_remove = [key for key, timestamp in self.recent_events.items() if timestamp < cutoff]
        for key in keys_to_remove:
            del self.recent_events[key]
            
        # Clean up old failures for all users
        usernames = list(self.auth_failures.keys())
        for username in usernames:
            self._cleanup_old_failures(username)
            # Remove users with no recent failures
            if not self.auth_failures[username]:
                del self.auth_failures[username]