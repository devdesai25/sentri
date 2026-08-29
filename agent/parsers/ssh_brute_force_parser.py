import re
import time
import subprocess
import logging
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List, Set
import ipaddress
import asyncio

from .base import BaseParser

logger = logging.getLogger('sentri.ssh_brute_force')

class SSHBruteForceParser(BaseParser):
    """
    Parser for detecting SSH brute force attempts based on failed login patterns.
    """
    
    # Default configuration
    DEFAULT_FAILURE_THRESHOLD = 5    # Block after this many failures
    DEFAULT_FAILURE_WINDOW = 5 * 60  # Look at failures in the last 5 minutes
    DEFAULT_BLOCK_MINUTES = 30       # Block IPs for 30 minutes
    
    def __init__(self, debug=False,
                failure_threshold=None,
                failure_window_minutes=None,
                block_minutes=None,
                enable_blocking=True,
                whitelist=None):
        """
        Initialize the SSH brute force parser.
        
        Args:
            debug: Enable debug logging
            failure_threshold: Number of failures before blocking (default: 5)
            failure_window_minutes: Window for counting failures in minutes (default: 5)
            block_minutes: How long to block IPs in minutes (default: 30)
            enable_blocking: Whether to enable automatic IP blocking (default: True)
            whitelist: List of IPs/networks to never block (default: None)
        """
        self.debug = debug
        
        # Configure thresholds
        self.failure_threshold = failure_threshold or self.DEFAULT_FAILURE_THRESHOLD
        self.failure_window = (failure_window_minutes or 5) * 60  # Convert to seconds
        self.block_minutes = block_minutes or self.DEFAULT_BLOCK_MINUTES
        self.enable_blocking = enable_blocking
        
        # IP tracking data structures
        self.ip_failures = {}        # IP -> list of failure timestamps
        self.user_failures = {}      # Username -> list of failure timestamps
        self.ip_user_failures = {}   # IP+User -> list of failure timestamps
        self.recent_alerts = set()   # Set of recently alerted IPs to avoid spam
        self.blocked_ips = {}        # IP -> unblock_time
        
        # Configure whitelist
        self.whitelist = set()
        self.whitelist_networks = []
        if whitelist:
            self._configure_whitelist(whitelist)
            
        # Patterns to match SSH authentication failures and invalid users
        # Updated based on the actual log format
        self.ssh_failure_patterns = [
            # Invalid user pattern - matches "Invalid user buntu from 49.36.91.220 port 52628"
            re.compile(
                r'Invalid user (?P<user>\S+) from (?P<ip_address>\S+) port \d+'
            ),
            # Failed authentication command - matches "AuthorizedKeysCommand /usr/share/.../eic_run_authorized_keys ubuntu SHA256:... failed"
            re.compile(
                r'AuthorizedKeysCommand.*(?P<user>\S+) .* failed'
            ),
            # Failed password attempts
            re.compile(
                r'Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip_address>\S+) port \d+'
            )
        ]
        
        # Track processed lines to avoid duplicates
        self.processed_lines = set()
        
        if debug:
            logger.setLevel(logging.DEBUG)
            logger.debug("SSH brute force parser initialized")
    
    def parse(self, log_line: str, metadata: Dict[str, Any] = None) -> Optional[Dict[str, Any]]:
        """
        Parse a log line to detect SSH brute force attempts.
        
        Args:
            log_line: The log line to parse
            metadata: Additional metadata about the log line
            
        Returns:
            Dict containing the event if a brute force attempt is detected, None otherwise.
        """
        if metadata is None:
            metadata = {}
            
        # Skip already processed lines
        line_hash = hash(log_line)
        if line_hash in self.processed_lines:
            return None
            
        # Add to processed lines
        self.processed_lines.add(line_hash)
        
        # Limit size of processed_lines set to avoid memory issues
        if len(self.processed_lines) > 10000:
            self.processed_lines = set(list(self.processed_lines)[-5000:])
        
        # For debugging
        if self.debug:
            logger.debug(f"Checking line for SSH brute force: {log_line}")
            
        # Skip lines that aren't related to SSH authentication issues
        if 'sshd' not in log_line:
            return None
            
        if not ('Invalid user' in log_line or 
                'failed' in log_line or 
                'Connection closed' in log_line or
                'Failed password' in log_line):
            return None
            
        # Try to extract timestamp from log line
        timestamp_match = re.match(r'(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})', log_line)
        log_timestamp = None
        if timestamp_match:
            log_timestamp = timestamp_match.group('timestamp')
        
        # Try to match against our failure patterns
        for pattern in self.ssh_failure_patterns:
            match = pattern.search(log_line)
            if match:
                event_data = match.groupdict()
                
                # Extract user and IP information
                if 'user' in event_data and 'ip_address' in event_data:
                    user = event_data['user']
                    ip_address = event_data['ip_address']
                elif 'user' in event_data:
                    # Special case for AuthorizedKeysCommand where we don't have IP in the same line
                    # Extract IP address from the Connection closed line
                    user = event_data['user']
                    
                    # For these lines, we don't have the IP in the match
                    # We need to check other lines with this pattern
                    if self.debug:
                        logger.debug(f"Found user {user} but no IP, recording partial failure")
                        
                    # Skip lines without IP address - incomplete information
                    continue
                else:
                    # Skip lines without user info
                    continue
                
                # Skip if IP is invalid
                if not self._is_valid_ip(ip_address):
                    continue
                    
                # Skip if IP is in whitelist
                if self._is_ip_whitelisted(ip_address):
                    if self.debug:
                        logger.debug(f"Skipping whitelisted IP {ip_address}")
                    continue
                
                if self.debug:
                    logger.debug(f"SSH failure detected: User={user}, IP={ip_address}")
                
                # Record the failure
                current_time = time.time()
                
                # Create a failure event for storage
                failure_event = {
                    'event': 'ssh_brute_force_attempt',
                    'timestamp': datetime.fromtimestamp(current_time).isoformat(),
                    'ip_address': ip_address,
                    'username': user,
                    'raw_log': log_line,
                    'source': metadata.get('source', 'auth.log')
                }
                
                # Add failure to tracking
                ip_failures = self._add_failure(ip_address, user, current_time)
                failure_event['failure_count'] = ip_failures
                
                # Check if threshold exceeded
                if ip_failures >= self.failure_threshold:
                    # Create brute force detection event
                    detection_event = {
                        'event': 'ssh_brute_force_detected',
                        'timestamp': datetime.fromtimestamp(current_time).isoformat(),
                        'ip_address': ip_address,
                        'username': user,
                        'failure_count': ip_failures,
                        'threshold': self.failure_threshold,
                        'window_minutes': self.failure_window // 60,
                        'is_blocked': False,
                        'block_minutes': self.block_minutes,
                        'raw_log': log_line,
                        'source': metadata.get('source', 'auth.log')
                    }
                    
                    # Apply blocking if enabled
                    if self.enable_blocking:
                        block_success = self._block_ip(ip_address)
                        detection_event['is_blocked'] = block_success
                        
                        # Send notification via API if we have access to an API client
                        if hasattr(self, 'api_client') and self.api_client:
                            try:
                                # Get event loop
                                loop = asyncio.get_event_loop()
                                # Schedule notification
                                asyncio.run_coroutine_threadsafe(
                                    self.api_client.send_brute_force_alert(
                                        ip_address=ip_address,
                                        username=user,
                                        failure_count=ip_failures,
                                        threshold=self.failure_threshold,
                                        is_blocked=block_success,
                                        block_minutes=self.block_minutes
                                    ), 
                                    loop
                                )
                                
                                if self.debug:
                                    logger.debug(f"API notification scheduled for brute force from {ip_address}")
                            except Exception as e:
                                logger.error(f"Error scheduling notification: {str(e)}")
                                
                    return detection_event
                
                # Just return the failure event
                return failure_event
                
        # No match found or no complete information
        return None
    
    def _add_failure(self, ip_address: str, username: str, timestamp: float) -> int:
        """
        Add a failure to tracking and return current count.
        
        Args:
            ip_address: The source IP
            username: The attempted username
            timestamp: Current timestamp
            
        Returns:
            Current failure count for this IP
        """
        # Initialize tracking structures if needed
        if ip_address not in self.ip_failures:
            self.ip_failures[ip_address] = []
        
        if username not in self.user_failures:
            self.user_failures[username] = []
            
        ip_user_key = f"{ip_address}:{username}"
        if ip_user_key not in self.ip_user_failures:
            self.ip_user_failures[ip_user_key] = []
        
        # Record this failure
        self.ip_failures[ip_address].append(timestamp)
        self.user_failures[username].append(timestamp)
        self.ip_user_failures[ip_user_key].append(timestamp)
        
        # Clean up old failures
        self._cleanup_old_failures()
        
        # Count recent failures
        return self._count_recent_failures(self.ip_failures[ip_address], timestamp)
    
    def _block_ip(self, ip_address: str) -> bool:
        """
        Block an IP address using iptables.
        
        Args:
            ip_address: IP to block
            
        Returns:
            True if successfully blocked, False otherwise
        """
        # Skip if already blocked
        if ip_address in self.blocked_ips:
            return True
            
        # Skip private IPs
        try:
            ip_obj = ipaddress.ip_address(ip_address)
            if ip_obj.is_private:
                logger.warning(f"Not blocking private IP {ip_address}")
                return False
        except ValueError:
            return False
            
        try:
            # Use iptables to block the IP
            cmd = ['iptables', '-A', 'INPUT', '-s', ip_address, '-p', 'tcp', 
                   '--dport', '22', '-j', 'REJECT', '--reject-with', 'tcp-reset']
            
            if self.debug:
                logger.debug(f"Running command: {' '.join(cmd)}")
                
            result = subprocess.run(cmd, check=True, capture_output=True)
            
            # Record block time
            unblock_time = time.time() + (self.block_minutes * 60)
            self.blocked_ips[ip_address] = unblock_time
            
            # Schedule unblock through cleanup process
            if self.debug:
                logger.debug(f"IP {ip_address} blocked until {datetime.fromtimestamp(unblock_time)}")
                
            return True
            
        except subprocess.CalledProcessError as e:
            error_msg = f"Failed to block IP: {e.stderr.decode() if e.stderr else str(e)}"
            logger.error(error_msg)
            return False
        except Exception as e:
            logger.error(f"Unexpected error blocking IP: {str(e)}")
            return False
    
    def _unblock_ip(self, ip_address: str) -> bool:
        """
        Unblock a previously blocked IP.
        
        Args:
            ip_address: IP to unblock
            
        Returns:
            True if successful, False otherwise
        """
        # Skip if not blocked
        if ip_address not in self.blocked_ips:
            return False
            
        try:
            # Use iptables to remove the block
            cmd = ['iptables', '-D', 'INPUT', '-s', ip_address, '-p', 'tcp', 
                   '--dport', '22', '-j', 'REJECT', '--reject-with', 'tcp-reset']
            
            if self.debug:
                logger.debug(f"Running command: {' '.join(cmd)}")
                
            result = subprocess.run(cmd, check=True, capture_output=True)
            
            # Remove from blocked IPs
            del self.blocked_ips[ip_address]
            
            if self.debug:
                logger.debug(f"IP {ip_address} unblocked")
                
            return True
            
        except subprocess.CalledProcessError as e:
            error_msg = f"Failed to unblock IP: {e.stderr.decode() if e.stderr else str(e)}"
            logger.error(error_msg)
            return False
        except Exception as e:
            logger.error(f"Unexpected error unblocking IP: {str(e)}")
            return False
    
    def _count_recent_failures(self, failures: List[float], current_time: float) -> int:
        """
        Count failures within the configured window.
        
        Args:
            failures: List of failure timestamps
            current_time: Current timestamp
            
        Returns:
            Count of failures within the window
        """
        cutoff_time = current_time - self.failure_window
        return sum(1 for t in failures if t >= cutoff_time)
    
    def _cleanup_old_failures(self) -> None:
        """Remove old failures outside our window to prevent memory growth."""
        current_time = time.time()
        cutoff_time = current_time - (self.failure_window * 2)  # Double the window for cleanup
        
        # Helper to filter out old timestamps
        def filter_old_timestamps(timestamps):
            return [t for t in timestamps if t >= cutoff_time]
            
        # Clean up IP failures
        for ip in list(self.ip_failures.keys()):
            self.ip_failures[ip] = filter_old_timestamps(self.ip_failures[ip])
            if not self.ip_failures[ip]:
                del self.ip_failures[ip]
                
        # Clean up user failures
        for user in list(self.user_failures.keys()):
            self.user_failures[user] = filter_old_timestamps(self.user_failures[user])
            if not self.user_failures[user]:
                del self.user_failures[user]
                
        # Clean up IP:user failures
        for key in list(self.ip_user_failures.keys()):
            self.ip_user_failures[key] = filter_old_timestamps(self.ip_user_failures[key])
            if not self.ip_user_failures[key]:
                del self.ip_user_failures[key]
                
        # Check for IPs to unblock
        for ip in list(self.blocked_ips.keys()):
            if self.blocked_ips[ip] <= current_time:
                self._unblock_ip(ip)
    
    def _is_valid_ip(self, ip_address: str) -> bool:
        """Check if a string is a valid IP address."""
        try:
            ipaddress.ip_address(ip_address)
            return True
        except ValueError:
            return False
    
    def _is_ip_whitelisted(self, ip_address: str) -> bool:
        """
        Check if an IP is in the whitelist.
        
        Args:
            ip_address: IP to check
            
        Returns:
            True if whitelisted, False otherwise
        """
        # Check if the IP is directly in the whitelist
        if ip_address in self.whitelist:
            return True
            
        # Check if the IP is in any whitelisted network
        try:
            ip_obj = ipaddress.ip_address(ip_address)
            for network in self.whitelist_networks:
                if ip_obj in network:
                    return True
        except ValueError:
            # If the IP is invalid, it's not whitelisted
            pass
            
        return False
    
    def _configure_whitelist(self, whitelist: List[str]) -> None:
        """
        Configure IP whitelist.
        
        Args:
            whitelist: List of IPs and networks (CIDR notation) to whitelist
        """
        for item in whitelist:
            if not item:
                continue
                
            try:
                # Check if it's a CIDR network
                if '/' in item:
                    network = ipaddress.ip_network(item, strict=False)
                    self.whitelist_networks.append(network)
                else:
                    # It's a single IP
                    ip = ipaddress.ip_address(item)
                    self.whitelist.add(item)
            except ValueError as e:
                logger.warning(f"Invalid whitelist entry '{item}': {e}")
    
    def cleanup_old_events(self) -> None:
        """Clean up old events to prevent memory growth."""
        self._cleanup_old_failures()
        
        # Clear alert set periodically to allow re-alerting for persistent attackers
        self.recent_alerts.clear()