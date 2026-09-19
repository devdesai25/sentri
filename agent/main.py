import asyncio
import argparse
import os
import signal
import sys
from datetime import datetime
import logging

# Add the parent directory to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from agent.core.agent import SentriAgent
from agent.watchers.file_watcher import FileWatcher
from agent.parsers.ssh_parser import SSHParser
from agent.storage.json_storage import JSONFileStorage

from agent.parsers.command_parser import AuditdCommandParser

from agent.api.client import ApiClient

from agent.parsers.privilege_escalation_parser import PrivilegeEscalationParser

from agent.parsers.ssh_brute_force_parser import SSHBruteForceParser

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('sentri')

# Global variables for shutdown handling
shutdown_event = None
tasks = []

async def main():
    """Main entry point for the Sentri agent"""
    global shutdown_event, tasks
    
    # Create an event for signaling shutdown
    shutdown_event = asyncio.Event()
    
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description='Sentri system monitoring agent')
    parser.add_argument('--ssh-log', type=str, 
                        help='Path to the SSH log file (default: auto-detect)',
                        default=None)
    parser.add_argument('--debug', action='store_true',
                        help='Enable debug logging')
    parser.add_argument('--from-beginning', action='store_true',
                        help='Process log file from the beginning instead of just new entries')
    parser.add_argument('--storage-dir', type=str,
                        help='Directory to store event logs (default: ./logs)',
                        default='./logs')
    parser.add_argument('--query', action='store_true',
                        help='Query mode: display stored events instead of monitoring')
    parser.add_argument('--event-type', type=str,
                        help='Filter events by type (with --query)')
    parser.add_argument('--user', type=str,
                        help='Filter events by username (with --query)')
    parser.add_argument('--ip', type=str,
                        help='Filter events by IP address (with --query)')
    parser.add_argument('--last', type=int,
                        help='Show only the last N events (with --query)')
    parser.add_argument('--stats', action='store_true',
                        help='Show event statistics')
    parser.add_argument('--auditd-log', type=str, 
                        help='Path to the auditd log file (default: /var/log/audit/audit.log)',
                        default='/var/log/audit/audit.log')
    parser.add_argument('--api-url', type=str,
                    help='URL of the Sentri API for risk assessment (e.g., http://localhost:8000/api/v1)',
                    default=None)
    parser.add_argument('--test-api', action='store_true',
                    help='Test API connectivity and exit')

    
    args = parser.parse_args()

    if args.test_api and api_client:
        print(f"Testing API connectivity to {args.api_url}...")
        try:
            if await api_client.test_connection():
                print("✅ API connection successful!")
            else:
                print("❌ API connection failed!")
            await api_client.close()
        except Exception as e:
            print(f"❌ API connection test error: {e}")
        return 0
        
    # Set log level based on debug flag
    if args.debug:
        logger.setLevel(logging.DEBUG)
        
    debug = args.debug
    seek_to_end = not args.from_beginning
    
    # Set up storage directory
    storage_dir = os.path.abspath(args.storage_dir)
    os.makedirs(storage_dir, exist_ok=True)

    api_client = None
    if args.api_url:
        api_client = ApiClient(args.api_url)
        print(f"Using API for command risk assessment: {args.api_url}")

    # Create storage backend
    storage_path = os.path.join(storage_dir, 'events.json')
    storage = JSONFileStorage(storage_path, api_client=api_client)
    
    # Query mode: display stored events and exit
    if args.query:
        return query_stored_events(storage, args)
    
    # Stats mode: show statistics and exit
    if args.stats:
        return show_statistics(storage)
    
    if debug:
        logger.debug("Debug mode enabled")
        logger.debug(f"Processing from {'new entries only' if seek_to_end else 'beginning of file'}")
        logger.debug(f"Storing events to {storage_path}")
    
    # Determine SSH log file location
    ssh_log_path = args.ssh_log
    if ssh_log_path is None:
        # Auto-detect based on common locations
        possible_paths = [
            '/var/log/auth.log',  # Debian/Ubuntu
            '/var/log/secure',    # RHEL/CentOS
            '/var/log/syslog'     # Fallback
        ]
        for path in possible_paths:
            if os.path.exists(path) and os.access(path, os.R_OK):
                ssh_log_path = path
                if debug:
                    logger.debug(f"Auto-detected log file at {ssh_log_path}")
                break
                
    if ssh_log_path is None or not os.path.exists(ssh_log_path):
        logger.error(f"Cannot find readable SSH log file. Please specify with --ssh-log")
        return 1
        
    print(f"Monitoring SSH log file: {ssh_log_path}")
    print(f"Storing events to: {storage_path}")

    # Create and configure the agent
    agent = SentriAgent(debug=debug, storage=storage)

    print("Setting up privilege escalation monitoring...")
    
    priv_esc_parser = PrivilegeEscalationParser(
        debug=debug,
        failure_threshold=3,                # Alert after 3 failures
        failure_window_minutes=30,          # Track failures for 30 minutes
        enable_lockout=True,                # Enable account lockout
        lockout_minutes=1,                 # Lock accounts for 15 minutes
        enable_termination=True             # Terminate sessions for locked users
    )
    agent.add_parser(priv_esc_parser)

    print("Setting up SSH brute force detection...")
    ssh_brute_force_parser = SSHBruteForceParser(
        debug=debug,
        failure_threshold=5,              # Block after 5 failures
        failure_window_minutes=5,         # Within a 5 minute window
        block_minutes=30,                 # Block for 30 minutes
        enable_blocking=True,             # Enable automatic blocking
        whitelist=['127.0.0.1', '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16']  # Never block internal IPs
    )
    agent.add_parser(ssh_brute_force_parser)

    # Test read a few lines to verify access
    try:
        with open(ssh_log_path, 'r') as f:
            test_lines = [f.readline() for _ in range(3)]
        if debug:
            logger.debug(f"Successfully read from log file. Example lines:")
            for i, line in enumerate(test_lines):
                if line.strip():
                    logger.debug(f"Line {i+1}: {line.strip()}")
    except Exception as e:
        logger.error(f"Error reading from log file: {str(e)}")
        if "Permission denied" in str(e):
            print("Hint: You may need to run this program with sudo or as root")
        return 1
    
    # Add the SSH parser
    ssh_parser = SSHParser(debug=debug)
    agent.add_parser(ssh_parser)

    # Add the file watcher for SSH logs
    ssh_watcher = FileWatcher(
        ssh_log_path,
        agent._process_log_line,
        seek_to_end=seek_to_end,
        debug=debug
    )
    agent.add_watcher(ssh_watcher)

    # Add the command parser with API client
    command_parser = AuditdCommandParser(debug=debug, api_client=api_client)
    agent.add_parser(command_parser)

    # Add auditd log watcher if available
    auditd_log_path = args.auditd_log
    if os.path.exists(auditd_log_path):
        try:
            # Test if we can read the file
            with open(auditd_log_path, 'r') as f:
                f.readline()
                
            print(f"Monitoring auditd log file: {auditd_log_path}")
            auditd_watcher = FileWatcher(
                auditd_log_path,
                agent._process_log_line,
                seek_to_end=seek_to_end,
                debug=debug
            )
            agent.add_watcher(auditd_watcher)
        except PermissionError:
            print(f"Cannot read {auditd_log_path} due to permission error.")
            print("Run the agent with sudo or ensure the user has permissions to read audit logs.")
        except Exception as e:
            print(f"Error setting up auditd log monitoring: {e}")
    else:
        print("Auditd logs not found. Command execution monitoring is disabled.")
        print("To enable command monitoring, install and configure auditd:")
        print("  sudo apt install auditd audispd-plugins           # Debian/Ubuntu")
        print("  sudo yum install audit audit-libs                 # RHEL/CentOS")
        print("  sudo auditctl -a exit,always -F arch=b64 -S execve -k commands")
    
    # Set up signal handlers for graceful shutdown
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(
            sig, lambda: asyncio.create_task(shutdown(agent))
        )
    
    # Start the agent
    await agent.start()
    
    # Add periodic cleanup task
    cleanup_task = asyncio.create_task(cleanup_tasks(agent, storage, debug))
    tasks.append(cleanup_task)
    
    # Wait for shutdown signal
    try:
        await shutdown_event.wait()
        logger.info("Shutdown initiated")
    except asyncio.CancelledError:
        logger.info("Main task cancelled")
    finally:
        # Make sure the agent stops even if we get here from an exception
        await agent.stop()
        
        # Cancel all tasks
        for task in tasks:
            if not task.done():
                task.cancel()
                
        # Wait for all tasks to complete with a timeout
        if tasks:
            try:
                await asyncio.wait(tasks, timeout=5)
            except asyncio.CancelledError:
                logger.debug("Task wait cancelled")
            
        logger.info("Shutdown complete")
    
    return 0

async def shutdown(agent):
    """Initiate graceful shutdown"""
    logger.info("Shutting down...")
    print("\nShutting down Sentri, please wait...")
    
    # Clean up API client if present
    for parser in agent.parsers:
        if hasattr(parser, 'api_client') and parser.api_client:
            await parser.api_client.close()
    
    # Signal all tasks to shut down
    shutdown_event.set()

async def cleanup_tasks(agent, storage, debug):
    """Periodic cleanup tasks"""
    try:
        while not shutdown_event.is_set():
            try:
                # Clean up old parser events
                for parser in agent.parsers:
                    if hasattr(parser, 'cleanup_old_events'):
                        parser.cleanup_old_events()
                        
                # Clean up old storage events (keep last 30 days)
                if storage:
                    deleted = storage.cleanup_old_events(max_age_days=30)
                    if deleted and debug:
                        logger.debug(f"Cleaned up {deleted} old events from storage")
                        
                # Run cleanup every hour
                await asyncio.wait_for(shutdown_event.wait(), timeout=3600)
            except asyncio.TimeoutError:
                # This is expected - timeout just means we continue with cleanup
                pass
            except Exception as e:
                logger.error(f"Error during cleanup: {e}")
                
    except asyncio.CancelledError:
        logger.debug("Cleanup task cancelled")
        raise

def query_stored_events(storage, args):
    """Query and display stored events"""
    events = storage.query_events(
        event_type=args.event_type,
        user=args.user,
        ip_address=args.ip,
        limit=args.last
    )
    
    if not events:
        print("No events found matching the criteria.")
        return 0
        
    print(f"Found {len(events)} events:")
    print("-" * 60)
    
    for event in events:
        timestamp = event.get('timestamp', 'unknown time')
        event_type = event.get('event', 'unknown')
        
        if event_type == 'ssh_login_success':
            user = event.get('user', 'unknown')
            ip = event.get('ip_address', 'unknown')
            method = event.get('auth_method', 'unknown')
            print(f"{timestamp} - SSH Login: User '{user}' from {ip} using {method}")
        elif event_type == 'ssh_login_failed':
            user = event.get('user', 'unknown')
            ip = event.get('ip_address', 'unknown')
            print(f"{timestamp} - Failed Login: User '{user}' from {ip}")
        elif event_type == 'ssh_invalid_user':
            user = event.get('user', 'unknown')
            ip = event.get('ip_address', 'unknown')
            print(f"{timestamp} - Invalid User: '{user}' from {ip}")
        elif event_type == 'command_execution':
            user = event.get('user', 'unknown')
            command = event.get('command', 'unknown')
            arguments = event.get('arguments', '')
            working_dir = event.get('working_directory', '')
            dir_info = f" in {working_dir}" if working_dir else ""
            print(f"{timestamp} - Command: User '{user}' ran '{command} {arguments}'{dir_info}")
        else:
            print(f"{timestamp} - {event_type}: {event}")
            
        print("-" * 60)
        
    return 0

def show_statistics(storage):
    """Show statistics about stored events"""
    stats = storage.get_stats()
    
    print("Sentri Event Statistics")
    print("=" * 40)
    print(f"Total events: {stats['total_events']}")
    print(f"Unique users: {stats['unique_users']}")
    print(f"Unique IP addresses: {stats['unique_ips']}")
    print(f"Storage file: {stats['storage_file']}")
    
    if stats['last_event_time']:
        print(f"Last event: {stats['last_event_time']}")
        
    print("\nEvents by type:")
    for event_type, count in stats['events_by_type'].items():
        print(f"  {event_type}: {count}")
        
    return 0

def run_main():
    """Run the main function and handle errors"""
    try:
        exit_code = asyncio.run(main())
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\nInterrupted by user. Exiting...")
        sys.exit(0)
    except Exception as e:
        logger.exception("Unhandled exception")
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == '__main__':
    run_main()