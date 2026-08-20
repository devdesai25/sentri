import aiohttp
import asyncio
import logging
from typing import Dict, Any, Optional
from datetime import datetime

logger = logging.getLogger('sentri.api_client')

class ApiClient:
    """Client for communicating with the Sentri API."""
    
    def __init__(self, api_url: str, timeout: int = 10):
        self.api_url = api_url.rstrip('/')
        self.timeout = timeout
        self.session = None
        self._closing = False
        
    async def get_session(self):
        """Get or create an aiohttp ClientSession."""
        if self.session is None or self.session.closed:
            self.session = aiohttp.ClientSession(
                headers={"Content-Type": "application/json"},
                timeout=aiohttp.ClientTimeout(total=self.timeout)
            )
        return self.session
        
    async def close(self):
        """Close the HTTP session."""
        if self._closing:
            return
            
        self._closing = True
        if self.session and not self.session.closed:
            await self.session.close()
            self.session = None
        self._closing = False
            
    async def assess_command_risk(self, command_event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Send a command to the backend API for risk assessment.
        
        Args:
            command_event: Command event data
            
        Returns:
            Dictionary with risk assessment or None if request failed
        """
        try:
            session = await self.get_session()
            
            # Format request data
            request_data = {
                "command": command_event.get("command", ""),
                "arguments": command_event.get("arguments", ""),
                "username": command_event.get("user", "unknown"),
                "working_directory": command_event.get("working_directory", ""),
                "timestamp": command_event.get("timestamp")
            }
            
            url = f"{self.api_url}/commands/risk-assessment"
            
            async with session.post(url, json=request_data) as response:
                if response.status != 200:
                    error_text = await response.text()
                    logger.error(f"API error ({response.status}): {error_text}")
                    return None
                    
                return await response.json()
                
        except aiohttp.ClientError as e:
            logger.error(f"HTTP error: {str(e)}")
        except asyncio.TimeoutError:
            logger.error(f"Request timed out after {self.timeout}s")
        except Exception as e:
            logger.error(f"Unexpected error in API request: {str(e)}")
            
        return None

    async def send_ssh_event(self, ssh_event: Dict[str, Any]) -> bool:
        """
        Send SSH event to the backend API.
        
        Args:
            ssh_event: SSH event data to send
            
        Returns:
            True if successful, False otherwise
        """
        try:
            session = await self.get_session()
            
            # Convert event format from agent to backend format
            backend_event = self._convert_ssh_event_format(ssh_event)
            
            url = f"{self.api_url}/ssh/events"
            
            async with session.post(url, json=backend_event) as response:
                if response.status in (200, 201, 202):
                    logger.debug(f"Successfully sent SSH event to API: {ssh_event.get('event')}")
                    return True
                else:
                    error_text = await response.text()
                    logger.error(f"API error sending SSH event ({response.status}): {error_text}")
                    return False
                
        except aiohttp.ClientError as e:
            logger.error(f"HTTP error sending SSH event: {str(e)}")
        except asyncio.TimeoutError:
            logger.error(f"SSH event request timed out after {self.timeout}s")
        except Exception as e:
            logger.error(f"Unexpected error in SSH event API request: {str(e)}")
            
        return False
    
    async def send_command_execution(self, command_event: Dict[str, Any]) -> bool:
        """
        Send command execution event to the backend API.
        
        Args:
            command_event: Command execution event data
            
        Returns:
            True if successful, False otherwise
        """
        try:
            session = await self.get_session()
            
            # Format request data
            request_data = {
                "command": command_event.get("command", ""),
                "arguments": command_event.get("arguments", ""),
                "timestamp": command_event.get("timestamp", datetime.now().isoformat()),
                "username": command_event.get("user", "unknown"),
                "host": command_event.get("metadata", {}).get("hostname", "unknown"),
                "working_directory": command_event.get("working_directory", ""),
                "exit_code": command_event.get("metadata", {}).get("exit_code"),
                "risk_level": command_event.get("risk_level", "unknown"),
                "event_metadata": {
                    "pid": command_event.get("pid", ""),
                    "original_event": command_event.get("event", "command_execution"),
                    "source": command_event.get("source", "unknown")
                }
            }
            
            url = f"{self.api_url}/command-executions"
            
            async with session.post(url, json=request_data) as response:
                if response.status in (200, 201, 202):
                    logger.debug(f"Successfully sent command execution event to API: {request_data.get('command')}")
                    return True
                else:
                    error_text = await response.text()
                    logger.error(f"API error sending command event ({response.status}): {error_text}")
                    return False
                
        except aiohttp.ClientError as e:
            logger.error(f"HTTP error sending command event: {str(e)}")
        except asyncio.TimeoutError:
            logger.error(f"Command event request timed out after {self.timeout}s")
        except Exception as e:
            logger.error(f"Unexpected error in command event API request: {str(e)}")
            
        return False
    
    async def send_privilege_escalation(self, priv_event: Dict[str, Any]) -> bool:
        """
        Send privilege escalation event to the backend API.
        
        Args:
            priv_event: Privilege escalation event data
            
        Returns:
            True if successful, False otherwise
        """
        try:
            session = await self.get_session()
            
            # Convert internal event format to backend API format
            request_data = {
                "username": priv_event.get("user", "unknown"),
                "target_user": priv_event.get("target_user", "root"),
                "method": self._get_escalation_method(priv_event),
                "command": priv_event.get("command", ""),
                "success": priv_event.get("success", False),
                "timestamp": priv_event.get("timestamp", datetime.now().isoformat()),
                "source_ip": None,  # Usually not available for local privilege escalation
                "event_metadata": {
                    "subtype": priv_event.get("subtype", "unknown"),
                    "description": priv_event.get("description", ""),
                    "threshold_exceeded": priv_event.get("threshold_exceeded", False),
                    "failure_count": priv_event.get("failure_count", 0),
                    "user_locked_out": priv_event.get("user_locked_out", False),
                    "source": priv_event.get("source", "unknown")
                }
            }
            
            url = f"{self.api_url}/privilege-escalations"
            
            async with session.post(url, json=request_data) as response:
                if response.status in (200, 201, 202):
                    logger.debug(f"Successfully sent privilege escalation event to API: {request_data.get('method')}")
                    return True
                else:
                    error_text = await response.text()
                    logger.error(f"API error sending privilege escalation event ({response.status}): {error_text}")
                    return False
                
        except aiohttp.ClientError as e:
            logger.error(f"HTTP error sending privilege escalation event: {str(e)}")
        except asyncio.TimeoutError:
            logger.error(f"Privilege escalation event request timed out after {self.timeout}s")
        except Exception as e:
            logger.error(f"Unexpected error in privilege escalation event API request: {str(e)}")
            
        return False
    
    async def send_brute_force_attempt(self, bf_event: Dict[str, Any]) -> bool:
        """
        Send brute force attempt event to the backend API.
        
        Args:
            bf_event: Brute force attempt event data
            
        Returns:
            True if successful, False otherwise
        """
        try:
            session = await self.get_session()
            
            # Convert to appropriate request format
            first_attempt = bf_event.get("timestamp", datetime.now().isoformat())
            last_attempt = bf_event.get("timestamp", datetime.now().isoformat())
            
            request_data = {
                "source_ip": bf_event.get("ip_address", "unknown"),
                "target_username": bf_event.get("username", "unknown"),
                "attempt_count": bf_event.get("failure_count", 1),
                "first_attempt": first_attempt,
                "last_attempt": last_attempt,
                "blocked": bf_event.get("is_blocked", False),
                "block_duration": bf_event.get("block_minutes", 0) * 60,  # Convert to seconds
                "event_metadata": {
                    "threshold": bf_event.get("threshold", 5),
                    "window_minutes": bf_event.get("window_minutes", 5),
                    "source": bf_event.get("source", "unknown")
                }
            }
            
            url = f"{self.api_url}/brute-force"
            
            async with session.post(url, json=request_data) as response:
                if response.status in (200, 201, 202):
                    logger.debug(f"Successfully sent brute force attempt event to API: {request_data.get('source_ip')}")
                    return True
                else:
                    error_text = await response.text()
                    logger.error(f"API error sending brute force attempt event ({response.status}): {error_text}")
                    return False
                
        except aiohttp.ClientError as e:
            logger.error(f"HTTP error sending brute force attempt event: {str(e)}")
        except asyncio.TimeoutError:
            logger.error(f"Brute force attempt event request timed out after {self.timeout}s")
        except Exception as e:
            logger.error(f"Unexpected error in brute force attempt event API request: {str(e)}")
            
        return False
    
    async def send_brute_force_alert(
        self, 
        ip_address: str,
        username: str,
        failure_count: int,
        threshold: int,
        is_blocked: bool,
        block_minutes: int = 0
    ) -> Dict[str, Any]:
        """
        Send notification about an SSH brute force attack.
        
        Args:
            ip_address: The attacker's IP address
            username: The username that was targeted
            failure_count: Number of failed attempts
            threshold: The configured threshold that was exceeded
            is_blocked: Whether the IP was blocked
            block_minutes: How long the IP was blocked for (if applicable)
            
        Returns:
            Response data or None if request failed
        """
        try:
            session = await self.get_session()
            
            # Format request data
            params = {
                "ip_address": ip_address,
                "username": username,
                "failure_count": failure_count,
                "threshold": threshold,
                "is_blocked": is_blocked,
                "block_minutes": block_minutes
            }
            
            url = f"{self.api_url}/ssh-security/brute-force-alert"
            
            async with session.post(url, params=params) as response:
                if response.status not in (200, 201, 202):
                    error_text = await response.text()
                    logger.error(f"API error ({response.status}): {error_text}")
                    return None
                    
                return await response.json()
                    
        except aiohttp.ClientError as e:
            logger.error(f"HTTP error in notification request: {str(e)}")
        except asyncio.TimeoutError:
            logger.error(f"Notification request timed out after {self.timeout}s")
        except Exception as e:
            logger.error(f"Unexpected error in notification API request: {str(e)}")
                
        return None
    
    def _convert_ssh_event_format(self, ssh_event: Dict[str, Any]) -> Dict[str, Any]:
        """Convert internal SSH event format to backend API format."""
        event_type = ssh_event.get("event", "unknown")
        
        # Map our event types to backend API event types
        event_type_mapping = {
            "ssh_login_success": "LOGIN_SUCCESS",
            "ssh_login_failed": "LOGIN_FAILURE",
            "ssh_invalid_user": "LOGIN_FAILURE",
            "ssh_connection_closed": "LOGOUT"
        }
        
        # Map our auth methods to backend API auth methods
        auth_method_mapping = {
            "password": "PASSWORD",
            "publickey": "PUBLICKEY",
            "keyboard-interactive": "KEYBOARD_INTERACTIVE",
            "unknown method": "UNKNOWN"
        }
        
        backend_event = {
            "event_type": event_type_mapping.get(event_type, "AUTHENTICATION_ATTEMPT"),
            "timestamp": ssh_event.get("timestamp", datetime.now().isoformat()),
            "username": ssh_event.get("user", "unknown"),
            "source_ip": ssh_event.get("ip_address", None),
            "source_host": ssh_event.get("source_host", None),
            "auth_method": auth_method_mapping.get(ssh_event.get("auth_method", "unknown method"), "UNKNOWN"),
            "success": event_type == "ssh_login_success",
            "raw_log": ssh_event.get("raw_log", None),
            "event_metadata": {
                "original_event": event_type,
                "source": ssh_event.get("source", "unknown")
            }
        }
        
        return backend_event
    
    def _get_escalation_method(self, priv_event: Dict[str, Any]) -> str:
        """Extract escalation method from privilege escalation event."""
        subtype = priv_event.get("subtype", "unknown")
        
        # Map our subtypes to backend API escalation methods
        method_mapping = {
            "sudo_exec": "SUDO",
            "sudo_auth_failure": "SUDO",
            "su_session_opened": "SU",
            "su_authentication_failure": "SU"
        }
        
        return method_mapping.get(subtype, "OTHER")

    async def test_connection(self) -> bool:
        """
        Test connection to the API.
        
        Returns:
            True if connection succeeded, False otherwise
        """
        try:
            session = await self.get_session()
            
            # Try to connect to the API root
            url = f"{self.api_url}/"
            
            async with session.get(url, timeout=self.timeout) as response:
                if response.status in (200, 201, 202):
                    logger.info(f"API connection test successful: {response.status}")
                    return True
                else:
                    error_text = await response.text()
                    logger.error(f"API connection test failed ({response.status}): {error_text}")
                    return False
                    
        except aiohttp.ClientError as e:
            logger.error(f"API connection test HTTP error: {str(e)}")
        except asyncio.TimeoutError:
            logger.error(f"API connection test timed out after {self.timeout}s")
        except Exception as e:
            logger.error(f"API connection test unexpected error: {str(e)}")
                
        return False