import asyncio
import os
import logging
from typing import Dict, List, Any, Optional

logger = logging.getLogger('sentri.agent')

class SentriAgent:
    """Main agent controller for Sentri"""
    
    def __init__(self, debug=False, storage=None):
        self.watchers = []
        self.parsers = []
        self.storage = storage
        self.running = False
        self.debug = debug
        
    def add_watcher(self, watcher):
        """Add a watcher to the agent"""
        self.watchers.append(watcher)
        
    def add_parser(self, parser):
        """Add a parser to the agent"""
        self.parsers.append(parser)
        
    def set_storage(self, storage):
        """Set the storage backend"""
        self.storage = storage
        
    def _process_log_line(self, log_line: str, metadata: Dict[str, Any]) -> None:
        """Process a new log line from a watcher"""
        if self.debug and 'sshd' in log_line:
            logger.debug(f"Processing SSH-related log line: {log_line}")
            
        # Try each parser until one succeeds
        for parser in self.parsers:
            try:
                event = parser.parse(log_line, metadata)
                if event:
                    self._process_event(event)
                    break
            except Exception as e:
                logger.error(f"Error parsing line with {parser.__class__.__name__}: {e}")
                
    def _process_event(self, event: Dict[str, Any]) -> None:
        """Process a structured event"""
        try:
            # Store the event if we have storage
            if self.storage:
                try:
                    self.storage.store_event(event)
                except Exception as e:
                    logger.error(f"Error storing event: {e}")
            
            # Print the event to the console
            event_type = event.get('event', 'unknown')
            
            if event_type == 'ssh_login_success':
                auth_method = event.get('auth_method', 'unknown method')
                ip_address = event.get('ip_address', 'unknown IP')
                user = event.get('user', 'unknown user')
                
                print(f"\nSSH Login Detected: User '{user}' logged in from {ip_address}" + 
                    (f" using {auth_method}" if auth_method != 'unknown method' else ""))
            elif event_type == 'ssh_login_failed':
                user = event.get('user', 'unknown user')
                ip_address = event.get('ip_address', 'unknown IP')
                auth_method = event.get('auth_method', 'unknown method')
                
                print(f"\nFailed SSH Login: User '{user}' failed to log in from {ip_address}" + 
                    (f" using {auth_method}" if auth_method != 'unknown method' else ""))
            elif event_type == 'ssh_invalid_user':
                user = event.get('user', 'unknown')
                ip_address = event.get('ip_address', 'unknown IP')
                print(f"\nInvalid SSH User: '{user}' from {ip_address}")
            elif event_type == 'ssh_connection_closed':
                ip_address = event.get('ip_address', 'unknown IP')
                user = event.get('user', 'unknown user')
                if user != 'unknown user':
                    print(f"\nSSH Connection Closed: User '{user}' from {ip_address}")
                else:
                    print(f"\nSSH Connection Closed: {ip_address}")
            elif event_type == 'command_execution':
                user = event.get('user', 'unknown user')
                command = event.get('command', 'unknown command')
                arguments = event.get('arguments', '')
                working_dir = event.get('working_directory', '')
                
                # Get risk assessment info if available
                risk_level = event.get('risk_level', 'unknown')
                risk_reason = event.get('risk_reason', '')
                
                # Format risk level with color coding
                risk_display = ""
                if risk_level != 'unknown':
                    # Color mapping for different risk levels
                    color_codes = {
                        'critical': '\033[1;31m',  # Bold Red
                        'high': '\033[31m',        # Red
                        'medium': '\033[33m',      # Yellow
                        'low': '\033[32m',         # Green
                        'minimal': '\033[36m'      # Cyan
                    }
                    # Reset code to return to normal terminal color
                    reset_code = '\033[0m'
                    
                    # Get appropriate color or default to reset
                    color = color_codes.get(risk_level.lower(), reset_code)
                    risk_display = f" [{color}{risk_level.upper()}{reset_code}]"
                
                dir_info = f" in {working_dir}" if working_dir else ""
                print(f"\nCommand Executed{risk_display}: User '{user}' ran '{command} {arguments}'{dir_info}")
                
                # Show risk reason if available
                if risk_reason:
                    print(f"Risk Assessment: {risk_reason}")
            elif event_type == 'privilege_escalation':
                subtype = event.get('subtype', 'unknown')
                success = event.get('success', False)
                description = event.get('description', 'Unknown privilege escalation event')
                
                # Format output with colors
                highlight = '\033[1;31m' if not success else '\033[1;33m'
                reset = '\033[0m'
                
                # Format the alert type based on subtype and success
                if subtype == 'sudo_exec':
                    alert_type = f"{highlight}SUDO EXECUTION{reset}"
                elif subtype == 'sudo_auth_failure':
                    alert_type = f"{highlight}FAILED SUDO ATTEMPT{reset}"
                elif subtype == 'su_session_opened':
                    alert_type = f"{highlight}PRIVILEGE ELEVATION{reset}"
                elif subtype == 'su_authentication_failure':
                    alert_type = f"{highlight}FAILED PRIVILEGE ELEVATION{reset}"
                else:
                    alert_type = f"{highlight}PRIVILEGE EVENT{reset}"
                
                # Print formatted alert
                print(f"\n{alert_type}")
                print(description)
                
                # Check if threshold has been exceeded
                if event.get('threshold_exceeded', False):
                    failure_count = event.get('failure_count', 0)
                    warning_msg = f"\033[1;41m ATTEMPTS EXCEEDED \033[0m User has {failure_count} failed attempts"
                    print(warning_msg)
                    
                # Check if user was locked out
                if event.get('user_locked_out', False):
                    lockout_msg = f"\033[1;44m ACCOUNT LOCKED \033[0m User has been locked out for {event.get('lockout_minutes', 15)} minutes"
                    print(lockout_msg)
                
                # Print success/failure status
                status = "\033[32m✓ Success\033[0m" if success else "\033[31m✗ Failed\033[0m"
                print(f"Status: {status}")
                
                # Print raw log in debug mode
                if self.debug and 'original_log' in event:
                    print(f"Log: {event['original_log']}")
                    
                # Print separator
                print("-" * 60)
            elif event_type == 'ssh_brute_force_attempt':
                # This case should no longer be triggered because we're not returning individual failures
                ip_address = event.get('ip_address', 'unknown')
                user = event.get('username', 'unknown')
                count = event.get('failure_count', 0)
                
                # Print with color coding for failed login attempts
                print(f"\n\033[33mSSH Login Failure\033[0m: User '{user}' from {ip_address}")
                print(f"Failures: {count}")
                
            elif event_type == 'ssh_brute_force_detected':
                ip_address = event.get('ip_address', 'unknown')
                user = event.get('username', 'unknown')
                count = event.get('failure_count', 0)
                threshold = event.get('threshold', 0)  # Get threshold from the event itself
                is_blocked = event.get('is_blocked', False)
                block_minutes = event.get('block_minutes', 0)
                
                # Print with alert formatting for brute force detection
                print(f"\n\033[1;41m SSH BRUTE FORCE ATTACK DETECTED \033[0m")
                print(f"IP: \033[1;31m{ip_address}\033[0m attempting user: \033[1;31m{user}\033[0m")
                print(f"Failed attempts: {count} (threshold: {threshold})")
                
                if is_blocked:
                    print(f"\033[1;32mIP has been blocked\033[0m for {block_minutes} minutes")
                else:
                    print("\033[1;33mIP was not blocked\033[0m - blocking disabled or failed")
            else:
                print(f"\nUnknown event: {event}")
                
            # Print a separator to make output more readable
            print("-" * 60)
        except Exception as e:
            logger.error(f"Error processing event: {e}")

    async def start(self) -> None:
        """Start the agent and all its watchers"""
        if self.running:
            return
            
        if self.debug:
            logger.debug("Starting Sentri agent")
            
        self.running = True
        
        try:
            # Start all watchers
            start_tasks = [watcher.start() for watcher in self.watchers]
            if start_tasks:
                await asyncio.gather(*start_tasks)
                
            if self.debug:
                logger.debug("All watchers started")
        except Exception as e:
            logger.error(f"Error starting watchers: {e}")
            self.running = False
            raise
            
    async def stop(self) -> None:
        """Stop the agent and all its watchers"""
        if not self.running:
            return
            
        logger.info("Stopping Sentri agent")
            
        self.running = False
        
        # Stop all watchers with proper error handling
        stop_errors = []
        for watcher in self.watchers:
            try:
                await watcher.stop()
            except Exception as e:
                stop_errors.append(f"Error stopping {watcher.__class__.__name__}: {e}")
                
        # Report any errors after attempting to stop all watchers
        for error in stop_errors:
            logger.error(error)
            
        # Close API clients in parsers
        for parser in self.parsers:
            if hasattr(parser, 'api_client') and parser.api_client:
                try:
                    await parser.api_client.close()
                    if self.debug:
                        logger.debug(f"Closed API client for {parser.__class__.__name__}")
                except Exception as e:
                    logger.error(f"Error closing API client for {parser.__class__.__name__}: {e}")
            
        # Close storage if available
        if self.storage:
            try:
                if hasattr(self.storage, 'close'):
                    self.storage.close()
                    if self.debug:
                        logger.debug("Storage closed")
                    
                # Close storage API client if it exists
                if hasattr(self.storage, 'api_client') and self.storage.api_client:
                    await self.storage.api_client.close()
                    if self.debug:
                        logger.debug("Closed storage API client")
            except Exception as e:
                logger.error(f"Error closing storage: {e}")
                
        if self.debug:
            logger.debug("All watchers stopped")