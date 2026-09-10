import logging
import httpx
from typing import List, Optional, Dict, Any
from fastapi import HTTPException
from datetime import datetime

from app.core.config import settings
from app.schemas.command import RiskLevel, CommandRiskResponse

logger = logging.getLogger(__name__)

class TelegramService:
    """Service for sending notifications to Telegram."""
    
    def __init__(self):
        self.bot_token = settings.TELEGRAM_BOT_TOKEN
        self.chat_ids = settings.TELEGRAM_CHAT_IDS
        self.api_url = f"https://api.telegram.org/bot{self.bot_token}"
        self.enabled = settings.TELEGRAM_ENABLED
    
    async def send_command_alert(
        self, 
        command: str, 
        arguments: str, 
        username: str, 
        risk_assessment: CommandRiskResponse,
        working_directory: Optional[str] = None,
        source_ip: Optional[str] = None
    ) -> bool:
        """
        Send alert about a risky command to configured Telegram chats.
        
        Args:
            command: The executed command
            arguments: Command arguments
            username: User who executed the command
            risk_assessment: Risk assessment with level and reason
            working_directory: Optional directory where command was executed
            source_ip: Optional source IP address
            
        Returns:
            True if alert was sent successfully, False otherwise
        """
        # Check if Telegram notifications are enabled
        if not self.enabled:
            logger.debug("Telegram notifications are disabled")
            return False
            
        # Check if we have required configuration
        if not self.bot_token or not self.chat_ids:
            logger.warning("Telegram bot token or chat IDs not configured")
            return False
        
        # Create a formatted message using Markdown
        message = self._format_alert_message(
            command, arguments, username, risk_assessment, 
            working_directory, source_ip
        )
        
        # Send to all configured chat IDs
        success = True
        for chat_id in self.chat_ids:
            try:
                await self._send_message(chat_id, message)
            except Exception as e:
                logger.error(f"Failed to send Telegram alert to chat {chat_id}: {str(e)}")
                success = False
        
        return success
    
    def _format_alert_message(
        self, 
        command: str, 
        arguments: str, 
        username: str, 
        risk_assessment: CommandRiskResponse,
        working_directory: Optional[str] = None,
        source_ip: Optional[str] = None
    ) -> str:
        """Format a message for Telegram with command details and risk assessment."""
        # Use emoji to indicate risk level
        risk_emoji = {
            RiskLevel.CRITICAL: "🚨",
            RiskLevel.HIGH: "⚠️",
            RiskLevel.MEDIUM: "⚡",
            RiskLevel.LOW: "ℹ️",
            RiskLevel.MINIMAL: "✅"
        }.get(risk_assessment.risk_level, "⚠️")
        
        # Format the message with Markdown
        message = (
            f"{risk_emoji} *{risk_assessment.risk_level.upper()} RISK COMMAND DETECTED* {risk_emoji}\n\n"
            f"*Command:* `{command} {arguments}`\n"
            f"*User:* `{username}`\n"
        )
        
        # Add optional fields if available
        if working_directory:
            message += f"*Directory:* `{working_directory}`\n"
        if source_ip:
            message += f"*Source IP:* `{source_ip}`\n"
        
        # Add risk assessment
        message += f"\n*Risk Assessment:*\n{risk_assessment.reason}\n\n"
        
        # Add timestamp
        message += f"_Detected by Sentri at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}_"
        
        return message
    
    async def _send_message(self, chat_id: int, text: str) -> Dict[str, Any]:
        """
        Send a message to a Telegram chat.
        
        Args:
            chat_id: Telegram chat ID
            text: Message text with Markdown formatting
            
        Returns:
            Telegram API response
        """
        endpoint = f"{self.api_url}/sendMessage"
        payload = {
            "chat_id": chat_id,
            "text": text,
            "parse_mode": "Markdown",  # Enable Markdown formatting
            "disable_web_page_preview": True
        }
        
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.post(endpoint, json=payload)
                response_data = response.json()
                
                if not response.is_success or not response_data.get("ok"):
                    error_msg = response_data.get("description", "Unknown error")
                    logger.error(f"Telegram API error: {error_msg}")
                    raise HTTPException(
                        status_code=500, 
                        detail=f"Failed to send Telegram message: {error_msg}"
                    )
                
                return response_data
                
        except httpx.TimeoutException:
            logger.error("Timeout while sending Telegram message")
            raise HTTPException(
                status_code=500,
                detail="Timeout while sending Telegram message"
            )
        except Exception as e:
            logger.exception(f"Unexpected error sending Telegram message: {str(e)}")
            raise HTTPException(
                status_code=500,
                detail=f"Failed to send Telegram message: {str(e)}"
            )
        
    async def send_brute_force_alert(
        self,
        ip_address: str,
        username: str,
        failure_count: int,
        threshold: int,
        is_blocked: bool,
        block_minutes: Optional[int] = 0
    ) -> bool:
        """
        Send alert about an SSH brute force attempt to configured Telegram chats.
        
        Args:
            ip_address: Attacker's IP address
            username: Target username
            failure_count: Number of failed attempts
            threshold: Configured threshold that was exceeded
            is_blocked: Whether the IP was blocked
            block_minutes: How long the IP was blocked for (if applicable)
            
        Returns:
            True if alert was sent successfully, False otherwise
        """
        # Check if Telegram notifications are enabled
        if not self.enabled:
            logger.debug("Telegram notifications are disabled")
            return False
            
        # Check if we have required configuration
        if not self.bot_token or not self.chat_ids:
            logger.warning("Telegram bot token or chat IDs not configured")
            return False
        
        # Create a formatted message using Markdown
        message = (
            f"🚨 *SSH BRUTE FORCE ATTACK DETECTED* 🚨\n\n"
            f"*IP Address:* `{ip_address}`\n"
            f"*Username:* `{username}`\n"
            f"*Failed Attempts:* `{failure_count}` (threshold: {threshold})\n"
        )
        
        # Add blocking information
        if is_blocked:
            message += f"*Status:* IP has been blocked for {block_minutes} minutes\n"
        else:
            message += "*Status:* IP was not blocked (blocking disabled or failed)\n"
        
        # Add timestamp
        message += f"\n_Detected by Sentri at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}_"
        
        # Send to all configured chat IDs
        success = True
        for chat_id in self.chat_ids:
            try:
                await self._send_message(chat_id, message)
            except Exception as e:
                logger.error(f"Failed to send Telegram brute force alert to chat {chat_id}: {str(e)}")
                success = False
        
        return success
            
    async def test_notification(self) -> Dict[str, Any]:
        """
        Send a test message to configured Telegram chats.
        
        Returns:
            Status of the test and any errors
        """
        if not self.enabled:
            return {"status": "disabled", "message": "Telegram notifications are disabled"}
            
        if not self.bot_token or not self.chat_ids:
            return {
                "status": "error", 
                "message": "Telegram bot token or chat IDs not configured"
            }
            
        results = []
        for chat_id in self.chat_ids:
            try:
                message = (
                    "*Sentri Test Notification* 🔍\n\n"
                    "This is a test message from your Sentri security system.\n"
                    "If you're seeing this, your Telegram notifications are working correctly!\n\n"
                    f"_Sent at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}_"
                )
                
                await self._send_message(chat_id, message)
                results.append({"chat_id": chat_id, "status": "success"})
                
            except Exception as e:
                results.append({
                    "chat_id": chat_id, 
                    "status": "error",
                    "error": str(e)
                })
                
        return {
            "status": "completed",
            "results": results,
            "success_count": len([r for r in results if r["status"] == "success"]),
            "error_count": len([r for r in results if r["status"] == "error"])
        }