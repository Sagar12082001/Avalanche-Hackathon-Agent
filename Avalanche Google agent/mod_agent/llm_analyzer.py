"""
LLM Analyzer Module

This module handles all LLM-based content analysis including:
- Gemini API integration
- Content moderation analysis
- Sentiment analysis
- Context understanding
- Ambiguous content classification
"""

import json
import re
import requests
import hashlib
import logging
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List
from dataclasses import dataclass

from .types import ChatMessage, APIConfig, CacheEntry
from .prompt import SYSTEM_PROMPT, build_user_prompt

logger = logging.getLogger(__name__)


@dataclass
class LLMAnalysisResult:
    """Result of LLM analysis."""
    action: str
    reason: str
    confidence: float
    timeout_seconds: int
    analysis_details: Dict[str, Any]
    processing_time: float


class LLMAnalyzer:
    """
    Advanced LLM-based content analyzer using Gemini API.
    """
    
    def __init__(self, api_config: APIConfig):
        """
        Initialize the LLM analyzer.
        
        Args:
            api_config: Configuration for API calls
        """
        self.api_config = api_config
        self.api_url = f"{api_config.base_url}/models/{api_config.model_name}:generateContent"
        
        # Caching system
        self.cache: Dict[str, CacheEntry] = {} if api_config.enable_caching else {}
        
        # Request tracking
        self.requests_made = 0
        self.successful_requests = 0
        self.failed_requests = 0
        self.total_processing_time = 0.0
        
        logger.info(f"LLMAnalyzer initialized with model: {api_config.model_name}")
        logger.info(f"Caching enabled: {api_config.enable_caching}")
    
    def analyze_message(self, message: ChatMessage, rules: List[str]) -> LLMAnalysisResult:
        """
        Analyze a message using the LLM for moderation decision.
        
        Args:
            message: ChatMessage to analyze
            rules: List of community rules to consider
            
        Returns:
            LLMAnalysisResult with analysis details
        """
        start_time = datetime.now()
        
        if not self.api_config.api_key:
            return self._create_fallback_result(
                "No API key configured",
                (datetime.now() - start_time).total_seconds()
            )
        
        # Check cache first
        cache_key = self._generate_cache_key(message.text, rules)
        cached_result = self._get_cached_response(cache_key)
        if cached_result:
            cached_result.processing_time = (datetime.now() - start_time).total_seconds()
            return cached_result
        
        try:
            # Make API request
            result = self._make_llm_request(message, rules)
            
            # Cache successful result
            if result.action != "error":
                self._cache_response(cache_key, result)
            
            result.processing_time = (datetime.now() - start_time).total_seconds()
            self.total_processing_time += result.processing_time
            
            return result
            
        except Exception as e:
            logger.error(f"LLM analysis failed: {e}")
            self.failed_requests += 1
            return self._create_fallback_result(
                f"LLM analysis failed: {str(e)}",
                (datetime.now() - start_time).total_seconds()
            )
    
    def _make_llm_request(self, message: ChatMessage, rules: List[str]) -> LLMAnalysisResult:
        """Make the actual LLM API request."""
        self.requests_made += 1
        
        user_prompt = build_user_prompt(message.text, rules)
        
        # Prepare enhanced payload
        payload = {
            "contents": [
                {
                    "parts": [
                        {
                            "text": f"{SYSTEM_PROMPT}\n\n{user_prompt}"
                        }
                    ]
                }
            ],
            "generationConfig": {
                "temperature": self.api_config.temperature,
                "maxOutputTokens": self.api_config.max_output_tokens,
                "responseMimeType": "text/plain"
            },
            "safetySettings": [
                {
                    "category": "HARM_CATEGORY_HARASSMENT",
                    "threshold": "BLOCK_NONE"
                },
                {
                    "category": "HARM_CATEGORY_HATE_SPEECH", 
                    "threshold": "BLOCK_NONE"
                },
                {
                    "category": "HARM_CATEGORY_SEXUALLY_EXPLICIT",
                    "threshold": "BLOCK_NONE"
                },
                {
                    "category": "HARM_CATEGORY_DANGEROUS_CONTENT",
                    "threshold": "BLOCK_NONE"
                }
            ]
        }
        
        headers = {
            "Content-Type": "application/json",
            "X-goog-api-key": self.api_config.api_key
        }
        
        logger.debug(f"Making LLM request for message: {message.text[:50]}...")
        
        # Make request with retry logic
        response = self._make_api_request_with_retry(payload, headers)
        
        # Parse response
        return self._parse_llm_response(response, message)
    
    def _make_api_request_with_retry(self, payload: Dict, headers: Dict) -> requests.Response:
        """Make API request with exponential backoff retry."""
        last_exception = None
        
        for attempt in range(self.api_config.max_retries + 1):
            try:
                response = requests.post(
                    self.api_url,
                    headers=headers,
                    json=payload,
                    timeout=self.api_config.timeout
                )
                
                # Handle different status codes
                if response.status_code == 200:
                    self.successful_requests += 1
                    return response
                elif response.status_code == 429:  # Rate limited
                    retry_after = int(response.headers.get('Retry-After', 60))
                    logger.warning(f"Rate limited, waiting {retry_after}s")
                    if attempt < self.api_config.max_retries:
                        time.sleep(retry_after)
                        continue
                elif response.status_code in [401, 403]:  # Auth errors
                    logger.error(f"Authentication failed: {response.status_code}")
                    raise requests.RequestException(f"Authentication failed: {response.status_code}")
                else:
                    logger.error(f"API request failed: {response.status_code} - {response.text}")
                    raise requests.RequestException(f"HTTP {response.status_code}")
                    
            except requests.RequestException as e:
                last_exception = e
                if attempt < self.api_config.max_retries:
                    wait_time = self.api_config.retry_delay * (2 ** attempt)
                    logger.warning(f"Request failed (attempt {attempt + 1}), retrying in {wait_time}s...")
                    time.sleep(wait_time)
                else:
                    logger.error(f"All retry attempts failed")
                    raise last_exception
        
        raise last_exception or requests.RequestException("Unknown error")
    
    def _parse_llm_response(self, response: requests.Response, message: ChatMessage) -> LLMAnalysisResult:
        """Parse the LLM response into a structured result."""
        try:
            response_data = response.json()
            
            # Extract response text
            if "candidates" in response_data and len(response_data["candidates"]) > 0:
                candidate = response_data["candidates"][0]
                if "content" in candidate and "parts" in candidate["content"]:
                    response_text = candidate["content"]["parts"][0]["text"].strip()
                else:
                    raise ValueError("Unexpected API response structure")
            else:
                raise ValueError("No candidates in API response")
            
            # Parse JSON from response
            result_data = self._extract_json_from_response(response_text)
            
            # Validate and enhance result
            validated_result = self._validate_llm_result(result_data, message)
            
            logger.debug(f"LLM analysis complete: {validated_result['action']} - {validated_result['reason']}")
            
            return LLMAnalysisResult(
                action=validated_result["action"],
                reason=validated_result["reason"],
                confidence=validated_result.get("confidence", 0.8),
                timeout_seconds=validated_result.get("timeout_seconds", 0),
                analysis_details={
                    "raw_response": response_text,
                    "model_used": self.api_config.model_name,
                    "temperature": self.api_config.temperature,
                    "message_length": len(message.text),
                    "user_id": message.user_id
                },
                processing_time=0.0  # Will be set by caller
            )
            
        except Exception as e:
            logger.error(f"Failed to parse LLM response: {e}")
            return self._create_error_result(f"Response parsing failed: {str(e)}")
    
    def _extract_json_from_response(self, response_text: str) -> Dict[str, Any]:
        """Extract JSON from LLM response text."""
        try:
            # Try to parse as direct JSON
            return json.loads(response_text)
        except json.JSONDecodeError:
            # Look for JSON within markdown code blocks
            json_match = re.search(r'```json\s*(\{.*?\})\s*```', response_text, re.DOTALL)
            if json_match:
                try:
                    return json.loads(json_match.group(1))
                except json.JSONDecodeError:
                    pass
            
            # Look for JSON within the text (without markdown)
            json_match = re.search(r'\{[^}]*\}', response_text, re.DOTALL)
            if json_match:
                try:
                    return json.loads(json_match.group())
                except json.JSONDecodeError:
                    pass
            
            # Try to extract key-value pairs manually
            action_match = re.search(r'"action"\s*:\s*"([^"]+)"', response_text)
            reason_match = re.search(r'"reason"\s*:\s*"([^"]+)"', response_text)
            
            if action_match and reason_match:
                return {
                    "action": action_match.group(1),
                    "reason": reason_match.group(1),
                    "timeout_seconds": 0
                }
            
            raise ValueError(f"Could not extract JSON from response: {response_text}")
    
    def _validate_llm_result(self, result_data: Dict[str, Any], message: ChatMessage) -> Dict[str, Any]:
        """Validate and enhance LLM result."""
        # Ensure required fields
        if "action" not in result_data or "reason" not in result_data:
            raise ValueError("Missing required fields in LLM response")
        
        action = result_data["action"].lower()
        if action not in ["allow", "remove", "mute", "timeout"]:
            logger.warning(f"Invalid action '{action}', defaulting to 'allow'")
            action = "allow"
        
        # Set timeout_seconds
        timeout_seconds = result_data.get("timeout_seconds", 0)
        if action == "timeout" and timeout_seconds <= 0:
            timeout_seconds = 300  # Default 5 minutes
        elif action != "timeout":
            timeout_seconds = 0
        
        # Add confidence score if not present
        confidence = result_data.get("confidence", 0.8)
        
        return {
            "action": action,
            "reason": result_data["reason"],
            "timeout_seconds": timeout_seconds,
            "confidence": confidence
        }
    
    def _generate_cache_key(self, message_text: str, rules: List[str]) -> str:
        """Generate cache key for message and rules."""
        content = f"{message_text}_{json.dumps(sorted(rules))}"
        return hashlib.md5(content.encode()).hexdigest()
    
    def _get_cached_response(self, cache_key: str) -> Optional[LLMAnalysisResult]:
        """Get cached response if available and not expired."""
        if not self.api_config.enable_caching or cache_key not in self.cache:
            return None
        
        entry = self.cache[cache_key]
        if datetime.now() - entry.timestamp > timedelta(seconds=entry.ttl):
            del self.cache[cache_key]
            return None
        
        logger.debug(f"Using cached LLM response")
        return entry.response
    
    def _cache_response(self, cache_key: str, result: LLMAnalysisResult) -> None:
        """Cache successful response."""
        if not self.api_config.enable_caching:
            return
        
        self.cache[cache_key] = CacheEntry(
            response=result,
            timestamp=datetime.now(),
            ttl=self.api_config.cache_ttl
        )
        
        # Cleanup old entries
        if len(self.cache) > 100:
            self._cleanup_cache()
    
    def _cleanup_cache(self) -> None:
        """Clean up expired cache entries."""
        now = datetime.now()
        expired_keys = [
            key for key, entry in self.cache.items()
            if now - entry.timestamp > timedelta(seconds=entry.ttl)
        ]
        for key in expired_keys:
            del self.cache[key]
        logger.debug(f"Cleaned up {len(expired_keys)} expired cache entries")
    
    def _create_fallback_result(self, reason: str, processing_time: float) -> LLMAnalysisResult:
        """Create fallback result when LLM is not available."""
        return LLMAnalysisResult(
            action="allow",
            reason=f"LLM not available: {reason}",
            confidence=0.0,
            timeout_seconds=0,
            analysis_details={"fallback": True, "error": reason},
            processing_time=processing_time
        )
    
    def _create_error_result(self, error_message: str) -> LLMAnalysisResult:
        """Create error result."""
        return LLMAnalysisResult(
            action="allow",
            reason=f"Analysis error: {error_message}",
            confidence=0.0,
            timeout_seconds=0,
            analysis_details={"error": True, "message": error_message},
            processing_time=0.0
        )
    
    def check_health(self) -> Dict[str, Any]:
        """Check LLM API health."""
        if not self.api_config.api_key:
            return {
                "healthy": False,
                "reason": "No API key configured",
                "status_code": None
            }
        
        try:
            payload = {
                "contents": [{"parts": [{"text": "Hello"}]}]
            }
            
            headers = {
                "Content-Type": "application/json",
                "X-goog-api-key": self.api_config.api_key
            }
            
            response = requests.post(
                self.api_url,
                headers=headers,
                json=payload,
                timeout=10
            )
            
            return {
                "healthy": response.status_code == 200,
                "status_code": response.status_code,
                "reason": "API accessible" if response.status_code == 200 else f"HTTP {response.status_code}"
            }
            
        except Exception as e:
            return {
                "healthy": False,
                "reason": f"Connection error: {str(e)}",
                "status_code": None
            }
    
    def get_stats(self) -> Dict[str, Any]:
        """Get LLM analyzer statistics."""
        success_rate = (self.successful_requests / max(1, self.requests_made)) * 100
        avg_processing_time = self.total_processing_time / max(1, self.successful_requests)
        
        return {
            "requests_made": self.requests_made,
            "successful_requests": self.successful_requests,
            "failed_requests": self.failed_requests,
            "success_rate": f"{success_rate:.1f}%",
            "average_processing_time": f"{avg_processing_time:.3f}s",
            "cache_size": len(self.cache),
            "model_name": self.api_config.model_name,
            "api_config": {
                "temperature": self.api_config.temperature,
                "max_output_tokens": self.api_config.max_output_tokens,
                "timeout": self.api_config.timeout,
                "max_retries": self.api_config.max_retries
            }
        }
    
    def clear_cache(self) -> int:
        """Clear the response cache."""
        cache_size = len(self.cache)
        self.cache.clear()
        logger.info(f"Cleared {cache_size} cached responses")
        return cache_size
