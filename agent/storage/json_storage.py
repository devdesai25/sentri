import os
import json
import time
import threading
import asyncio
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Set, Tuple

from .base import BaseStorage
from agent.api.client import ApiClient  # Import ApiClient

import logging

logger = logging.getLogger('sentri.storage')

class JSONFileStorage(BaseStorage):
    """Storage backend that uses a JSON file with optional API forwarding"""
    
    def __init__(self, filepath: str, flush_interval: int = 5, api_client: Optional[ApiClient] = None):
        """
        Initialize a JSON file storage backend.
        
        Args:
            filepath: Path to the JSON file
            flush_interval: How often to flush to disk in seconds
            api_client: Optional API client for sending events to backend
        """
        self.filepath = filepath
        self.flush_interval = flush_interval
        self.events = []
        self.buffer = []
        self.lock = threading.Lock()
        self.last_flush = time.time()
        self.api_client = api_client
        self.stats = {
            'total_events': 0,
            'events_by_type': {},
            'unique_users': set(),
            'unique_ips': set()
        }
        
        # Create directory if it doesn't exist
        os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)
        
        # Load existing events if the file exists
        if os.path.exists(filepath):
            try:
                with open(filepath, 'r') as f:
                    data = json.load(f)
                    if isinstance(data, list):
                        self.events = data
                        
                        # Update statistics
                        self._update_stats_from_events(self.events)
            except Exception as e:
                print(f"Warning: Error loading events from {filepath}: {e}")
                # If we couldn't load the file, we'll just start with an empty list
                self.events = []
    
    def store_event(self, event: Dict[str, Any]) -> None:
        """
        Store an event in the storage backend and optionally send to API.
        
        Args:
            event: The event to store
        """
        # Make a copy of the event to avoid modifying the original
        event_copy = event.copy()
        
        # Ensure the event has a timestamp
        if 'timestamp' not in event_copy:
            event_copy['timestamp'] = datetime.now().isoformat()
        elif isinstance(event_copy['timestamp'], datetime):
            event_copy['timestamp'] = event_copy['timestamp'].isoformat()
            
        # Add storage timestamp (when we stored it)
        event_copy['stored_at'] = datetime.now().isoformat()
        
        with self.lock:
            # Append to the buffer
            self.buffer.append(event_copy)
            
            # Update statistics
            self.stats['total_events'] += 1
            
            event_type = event_copy.get('event', 'unknown')
            if event_type in self.stats['events_by_type']:
                self.stats['events_by_type'][event_type] += 1
            else:
                self.stats['events_by_type'][event_type] = 1
                
            if 'user' in event_copy:
                self.stats['unique_users'].add(event_copy['user'])
                
            if 'ip_address' in event_copy:
                self.stats['unique_ips'].add(event_copy['ip_address'])
            
            # Check if we need to flush to disk
            current_time = time.time()
            if current_time - self.last_flush > self.flush_interval:
                self._flush_to_disk()
        
        # Send to API if configured - this is done outside the lock to avoid blocking
        if self.api_client:
            asyncio.create_task(self._send_to_api(event_copy))
                
    def query_events(self, 
                     event_type: Optional[str] = None,
                     user: Optional[str] = None, 
                     ip_address: Optional[str] = None,
                     start_time: Optional[str] = None,
                     end_time: Optional[str] = None,
                     limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """
        Query events from storage based on search criteria.
        
        Args:
            event_type: Filter by event type (e.g., ssh_login_success)
            user: Filter by username
            ip_address: Filter by IP address
            start_time: Filter events after this time (ISO format)
            end_time: Filter events before this time (ISO format)
            limit: Maximum number of events to return
            
        Returns:
            List of events matching the criteria
        """
        # Ensure buffer is flushed before querying
        with self.lock:
            if self.buffer:
                self._flush_to_disk()
                
            # Copy the events to avoid threading issues
            all_events = self.events.copy()
            
        # Parse timestamps if provided
        start_dt = None
        end_dt = None
        
        if start_time:
            if isinstance(start_time, str):
                start_dt = datetime.fromisoformat(start_time)
            else:
                start_dt = start_time
                
        if end_time:
            if isinstance(end_time, str):
                end_dt = datetime.fromisoformat(end_time)
            else:
                end_dt = end_time
                
        # Filter the events
        filtered_events = []
        
        for event in all_events:
            # Check event type
            if event_type and event.get('event') != event_type:
                continue
                
            # Check user
            if user and event.get('user') != user:
                continue
                
            # Check IP address
            if ip_address and event.get('ip_address') != ip_address:
                continue
                
            # Check start time
            if start_dt:
                try:
                    event_time = datetime.fromisoformat(event.get('timestamp'))
                    if event_time < start_dt:
                        continue
                except (ValueError, TypeError):
                    # Skip events with invalid timestamps
                    continue
                    
            # Check end time
            if end_dt:
                try:
                    event_time = datetime.fromisoformat(event.get('timestamp'))
                    if event_time > end_dt:
                        continue
                except (ValueError, TypeError):
                    # Skip events with invalid timestamps
                    continue
                    
            filtered_events.append(event)
            
        # Apply limit if provided
        if limit is not None and limit > 0:
            filtered_events = filtered_events[-limit:]
            
        return filtered_events
        
    def get_stats(self) -> Dict[str, Any]:
        """
        Get statistics about stored events.
        
        Returns:
            Dict containing event statistics
        """
        with self.lock:
            # Make a copy of the stats to avoid threading issues
            stats_copy = {
                'total_events': self.stats['total_events'],
                'events_by_type': self.stats['events_by_type'].copy(),
                'unique_users': len(self.stats['unique_users']),
                'unique_ips': len(self.stats['unique_ips']),
                'storage_file': self.filepath,
                'last_event_time': None
            }
            
            # Get the timestamp of the last event
            if self.events:
                last_event = self.events[-1]
                stats_copy['last_event_time'] = last_event.get('timestamp')
                
            return stats_copy
            
    def cleanup_old_events(self, max_age_days: int = 30) -> int:
        """
        Delete events older than the specified age.
        
        Args:
            max_age_days: Maximum age of events in days
            
        Returns:
            Number of events deleted
        """
        cutoff_time = datetime.now() - timedelta(days=max_age_days)
        cutoff_iso = cutoff_time.isoformat()
        
        with self.lock:
            # Ensure buffer is flushed before cleanup
            if self.buffer:
                self._flush_to_disk()
                
            original_count = len(self.events)
            
            # Filter out events older than cutoff
            self.events = [
                event for event in self.events
                if event.get('timestamp', cutoff_iso) >= cutoff_iso
            ]
            
            deleted_count = original_count - len(self.events)
            
            if deleted_count > 0:
                # Save the updated events
                self._save_events_to_disk()
                
                # Reset statistics and recompute from events
                self._reset_stats()
                self._update_stats_from_events(self.events)
                
            return deleted_count
    
    async def _send_to_api(self, event: Dict[str, Any]) -> bool:
        """
        Send event to the backend API based on event type.
        
        Args:
            event: Event to send
            
        Returns:
            True if successfully sent, False otherwise
        """
        if not self.api_client:
            return False
            
        event_type = event.get('event', 'unknown')
        
        try:
            if event_type.startswith('ssh_'):
                # SSH events
                return await self.api_client.send_ssh_event(event)
            elif event_type == 'command_execution':
                # Command execution events
                return await self.api_client.send_command_execution(event)
            elif event_type == 'privilege_escalation':
                # Privilege escalation events
                return await self.api_client.send_privilege_escalation(event)
            elif event_type in ('ssh_brute_force_attempt', 'ssh_brute_force_detected'):
                # Brute force events
                return await self.api_client.send_brute_force_attempt(event)
            else:
                logger.warning(f"Unknown event type for API forwarding: {event_type}")
                return False
        except Exception as e:
            logger.error(f"Error sending event to API: {e}")
            return False
    
    def _flush_to_disk(self) -> None:
        """Flush buffered events to disk"""
        if not self.buffer:
            return
            
        # Append buffer to events
        self.events.extend(self.buffer)
        
        # Save all events to disk
        self._save_events_to_disk()
        
        # Clear the buffer
        self.buffer = []
        
        # Update the last flush time
        self.last_flush = time.time()
        
    def _save_events_to_disk(self) -> None:
        """Save all events to disk"""
        try:
            with open(self.filepath, 'w') as f:
                json.dump(self.events, f, indent=2)
        except Exception as e:
            print(f"Error saving events to {self.filepath}: {e}")
            
    def _reset_stats(self) -> None:
        """Reset statistics"""
        self.stats = {
            'total_events': 0,
            'events_by_type': {},
            'unique_users': set(),
            'unique_ips': set()
        }
        
    def _update_stats_from_events(self, events: List[Dict[str, Any]]) -> None:
        """Update statistics from a list of events"""
        for event in events:
            self.stats['total_events'] += 1
            
            event_type = event.get('event', 'unknown')
            if event_type in self.stats['events_by_type']:
                self.stats['events_by_type'][event_type] += 1
            else:
                self.stats['events_by_type'][event_type] = 1
                
            if 'user' in event:
                self.stats['unique_users'].add(event['user'])
                
            if 'ip_address' in event:
                self.stats['unique_ips'].add(event['ip_address'])
                
    def close(self) -> None:
        """Close the storage, ensuring all data is flushed"""
        if hasattr(self, 'lock'):  # Check if we have a lock attribute
            with self.lock:
                if hasattr(self, 'buffer') and self.buffer:  # Check for buffer attribute
                    try:
                        self._flush_to_disk()
                    except Exception as e:
                        logger.error(f"Error flushing to disk during close: {e}")