import httpx
import json
import logging
from typing import Dict, Any
from agentsentry.config import AgentSentryConfig

logger = logging.getLogger("AgentSentry.Services.Gemini")

async def call_gemini_reviewer(config: AgentSentryConfig, diff_content: str) -> Dict[str, Any]:
    """
    Invokes the Gemini 1.5 Pro / 2.0 Flash API to perform static vulnerability audits
    and parse structured JSON output.
    """
    # Use gemini_api_key if available in config (add this to AgentSentryConfig later if needed)
    api_key = getattr(config, 'gemini_api_key', None)
    if not api_key:
        logger.error("Cannot call Gemini API: GEMINI_API_KEY is missing.")
        return {
            "score": 0.0,
            "vulnerabilities": [{
                "file": "config.py",
                "line": 1,
                "severity": "CRITICAL",
                "issue": "Security Key Missing (GEMINI_API_KEY environment variable is not defined)",
                "remediation": "Export GEMINI_API_KEY in the environment before starting."
            }],
            "execution_command": ""
        }

    endpoint = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-pro:generateContent?key={api_key}"
    
    system_instruction = (
        "You are an Elite DevSecOps security reviewer. Analyze the git diff provided and audit "
        "it for vulnerabilities (SQL injection, credential leak, path traversals, or dangerous command injections).\n"
        "Return a JSON object conforming exactly to this schema:\n"
        "{\n"
        "  \"score\": float (0.0 to 10.0 representing code health and safety),\n"
        "  \"vulnerabilities\": [\n"
        "    {\n"
        "      \"file\": \"string (filename)\",\n"
        "      \"line\": integer,\n"
        "      \"severity\": \"string (LOW, MEDIUM, HIGH, CRITICAL)\",\n"
        "      \"issue\": \"string description\",\n"
        "      \"remediation\": \"string suggestion\"\n"
        "    }\n"
        "  ],\n"
        "  \"execution_command\": \"string (the terminal command to run unit tests/verification files, or blank if none)\"\n"
        "}"
    )

    prompt = f"{system_instruction}\n\n--- GIT DIFF FOR REVIEW ---\n{diff_content}"
    
    payload = {
        "contents": [
            {
                "parts": [{"text": prompt}]
            }
        ],
        "generationConfig": {
            "responseMimeType": "application/json",
            "temperature": 0.1
        }
    }

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(endpoint, json=payload)
            if response.status_code != 200:
                logger.error(f"Gemini API returned error code {response.status_code}: {response.text}")
                return {"score": 5.0, "vulnerabilities": [], "execution_command": ""}
            
            result = response.json()
            text_response = result["candidates"][0]["content"]["parts"][0]["text"]
            
            # Parse structured JSON output
            return json.loads(text_response)
    except Exception as e:
        logger.error(f"Error communicating with Gemini API: {str(e)}")
        return {"score": 5.0, "vulnerabilities": [], "execution_command": ""}
