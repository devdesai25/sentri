import json
import httpx
import logging
from fastapi import HTTPException
from typing import Dict, Any, Optional

from app.core.config import settings
from app.schemas.command import CommandRiskRequest, CommandRiskResponse, RiskLevel, ExplanationSection, CommandExplainRequest, CommandExplainResponse

logger = logging.getLogger(__name__)


class OpenAIService:
    """Service for interacting with the OpenAI API."""
    
    async def assess_command_risk(self, command_data: CommandRiskRequest) -> CommandRiskResponse:
        """
        Assess the security risk level of a command using OpenAI.
        
        Args:
            command_data: Data about the command execution
            
        Returns:
            Risk assessment with level and explanation
        """
        try:
            # System prompt instructing the LLM what to do
            system_prompt = """
            You are a Linux security expert analyzing commands for potential security risks.
            Evaluate the given command and classify it into one of these risk levels:
            
            - critical: Commands that could cause severe system damage, data loss, or security breaches
              Examples: rm -rf /, dd if=/dev/zero of=/dev/sda, wget malicious_script | bash
            
            - high: Commands that modify system configuration, add users, change permissions
              Examples: chmod 777 /etc/passwd, useradd, visudo, chown -R
            
            - medium: Commands that access sensitive data or establish network connections
              Examples: cat /etc/shadow, ssh, nc, curl with credentials
            
            - low: Information gathering or standard utility commands
              Examples: ls, find, ps, grep

            - minimal: Basic navigation or display commands
              Examples: cd, pwd, echo, date
            
            Analyze the full context including:
            - The command itself and its arguments
            - User executing the command (root is higher risk)
            - Working directory (commands in system directories may be higher risk)
            
            Respond ONLY with a JSON object containing:
            {
              "risk_level": "one of [critical, high, medium, low, minimal]",
              "reason": "brief explanation of risk assessment"
            }
            """
            
            # User prompt containing the command to analyze
            user_prompt = f"""
            Analyze this command execution:
            
            Command: {command_data.command}
            Arguments: {command_data.arguments}
            Username: {command_data.username}
            Working Directory: {command_data.working_directory or "unknown"}
            """
            
            # Prepare request to OpenAI API
            openai_url = "https://api.openai.com/v1/chat/completions"
            headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {settings.OPENAI_API_KEY}"
            }
            
            payload = {
                "model": "gpt-4.1-nano",  # Or other suitable model
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                "temperature": 0.1,  # Low temperature for consistent responses
                "max_tokens": 300
            }

            # Make API call to OpenAI
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.post(
                    openai_url,
                    headers=headers,
                    json=payload
                )
                
                if response.status_code != 200:
                    logger.error(f"OpenAI API error: {response.text}")
                    raise HTTPException(
                        status_code=500,
                        detail="Error communicating with OpenAI API"
                    )
                
                response_data = response.json()
                
            # Extract and parse response
            ai_response = response_data["choices"][0]["message"]["content"].strip()
            
            try:
                # Parse JSON response
                risk_data = json.loads(ai_response)
                
                # Validate the returned risk level
                risk_level = risk_data.get("risk_level", "").lower()
                
                if risk_level not in [e.value for e in RiskLevel]:
                    logger.warning(f"Invalid risk level '{risk_level}' returned by OpenAI, defaulting to medium")
                    risk_level = "medium"
                
                reason = risk_data.get("reason", "No reason provided by risk assessment engine")
                
                return CommandRiskResponse(risk_level=risk_level, reason=reason)
            
            except json.JSONDecodeError:
                logger.error(f"Failed to parse OpenAI response as JSON: {ai_response}")
                return CommandRiskResponse(
                    risk_level="medium",
                    reason="Error parsing risk assessment. Defaulting to medium risk."
                )
                
        except HTTPException:
            # Re-raise HTTP exceptions
            raise
        except Exception as e:
            logger.exception(f"Unexpected error in command risk assessment: {str(e)}")
            return CommandRiskResponse(
                risk_level="medium",
                reason=f"Error during risk assessment: {str(e)}. Defaulting to medium risk."
            )
    
    async def explain_command(self, command_data: CommandExplainRequest) -> CommandExplainResponse:
        """
        Generate an explanation for a shell command using OpenAI.
        
        Args:
            command_data: Data about the command to explain
                
        Returns:
            Structured explanation of the command with risk assessment
        """
        try:
            # System prompt instructing the LLM what to do
            system_prompt = """
            You are Sentri's command explanation system, designed to analyze Linux/Unix commands.
            
            IMPORTANT FORMATTING INSTRUCTIONS:
            1. ONLY respond with the EXACT sections requested in the user's message
            2. DO NOT add any additional sections, prefixes, or explanatory notes
            3. DO NOT include any markdown formatting beyond the section headers
            4. Keep explanations factual, concise and technically accurate
            5. NEVER include introductions, conclusions or additional commentary
            
            For risk assessment:
            - Categorize commands ONLY as: "critical", "high", "medium", "low", or "minimal"
            - Use ONLY these classifications, not variations like "very high" or "moderate"
            - Base risk levels on potential system impact, privilege escalation, or data loss
            - Ensure the risk level appears explicitly in the Potential Risks section
            
            Each response MUST be parseable by automated systems - strict adherence to format is required.
            """
            
            # User prompt with the command to explain
            user_prompt = f"""
            Explain this command: {command_data.command} {command_data.arguments}
            
            YOUR RESPONSE MUST CONTAIN EXACTLY THESE SECTIONS WITH PRECISELY THESE HEADERS:
            
            ## Purpose
            (1-2 sentences summarizing what the command does)
            
            ## Command Components
            (Explain each part of the command, its flags and arguments)
            
            ## Expected Output
            (Describe what output will be displayed when running this command)
            
            ## Common Use Cases
            (List typical scenarios where this command would be used)
            
            ## Potential Risks
            (Identify security implications and EXPLICITLY state the risk level as one of: "critical", "high", "medium", "low", or "minimal" with justification)
            """
            
            if command_data.context:
                user_prompt += f"\n\nAdditional context: {command_data.context}"
            
            # Prepare request to OpenAI API
            openai_url = "https://api.openai.com/v1/chat/completions"
            headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {settings.OPENAI_API_KEY}"
            }
            
            payload = {
                "model": "gpt-4.1-nano",  # Or other suitable model
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                "temperature": 0.2,  # Low temperature for consistent responses
                "max_tokens": 800
            }

            # Make API call to OpenAI
            async with httpx.AsyncClient(timeout=15.0) as client:
                response = await client.post(
                    openai_url,
                    headers=headers,
                    json=payload
                )
                
                if response.status_code != 200:
                    logger.error(f"OpenAI API error: {response.text}")
                    raise HTTPException(
                        status_code=500,
                        detail="Error communicating with OpenAI API"
                    )
                
                response_data = response.json()
                
            # Extract and parse response
            explanation_text = response_data["choices"][0]["message"]["content"].strip()
            
            # Parse the explanation into structured sections
            sections = self._parse_explanation_sections(explanation_text)
            
            # Extract risk level and summary
            risk_level, risk_explanation = self._extract_risk_info(sections)
            summary = self._extract_summary(sections)
            
            return CommandExplainResponse(
                command=f"{command_data.command} {command_data.arguments}".strip(),
                summary=summary,
                sections=sections,
                risk_level=risk_level,
                risk_explanation=risk_explanation
            )
                
        except HTTPException:
            # Re-raise HTTP exceptions
            raise
        except Exception as e:
            logger.exception(f"Unexpected error in command explanation: {str(e)}")
            # Return a basic response with error info
            return CommandExplainResponse(
                command=f"{command_data.command} {command_data.arguments}".strip(),
                summary=f"Error generating explanation: {str(e)}",
                sections=[
                    ExplanationSection(
                        title="Error", 
                        content="Failed to generate command explanation. Please try again later."
                    )
                ],
                risk_level=RiskLevel.MEDIUM,
                risk_explanation="Unable to assess risk due to explanation failure."
            )

    def _parse_explanation_sections(self, text: str) -> list[ExplanationSection]:
        """Parse the explanation response from OpenAI into structured sections."""
        sections = []
        current_section = None
        current_content = []
        
        # Split the text into lines and process
        lines = text.split('\n')
        for line in lines:
            # Check if this line starts a new section
            if line.startswith('## '):
                # Save the previous section if it exists
                if current_section:
                    sections.append(ExplanationSection(
                        title=current_section,
                        content='\n'.join(current_content).strip()
                    ))
                # Start a new section
                current_section = line.replace('## ', '').strip()
                current_content = []
            else:
                # Add to the current section content
                current_content.append(line)
        
        # Add the last section
        if current_section and current_content:
            sections.append(ExplanationSection(
                title=current_section,
                content='\n'.join(current_content).strip()
            ))
        
        return sections

    def _extract_risk_info(self, sections: list[ExplanationSection]) -> tuple[RiskLevel, Optional[str]]:
        """Extract risk level and explanation from the sections."""
        for section in sections:
            if section.title.lower() == "potential risks":
                content = section.content.lower()
                risk_explanation = section.content
                
                # Look for risk level mentions in the content
                if "critical" in content:
                    return RiskLevel.CRITICAL, risk_explanation
                elif "high" in content:
                    return RiskLevel.HIGH, risk_explanation
                elif "medium" in content:
                    return RiskLevel.MEDIUM, risk_explanation
                elif "low" in content:
                    return RiskLevel.LOW, risk_explanation
                elif "minimal" in content:
                    return RiskLevel.MINIMAL, risk_explanation
                
                # Default if no clear risk level is mentioned
                return RiskLevel.MEDIUM, risk_explanation
        
        # If no risk section found
        return RiskLevel.MEDIUM, None

    def _extract_summary(self, sections: list[ExplanationSection]) -> str:
        """Extract summary from the Purpose section."""
        for section in sections:
            if section.title.lower() == "purpose":
                return section.content
        return "No summary available"