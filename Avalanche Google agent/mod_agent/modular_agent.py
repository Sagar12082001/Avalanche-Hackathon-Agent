"""
Modular Chat Moderation Agent

This is the main orchestrating agent that coordinates between:
- spam_detector.py: Advanced spam detection
- llm_analyzer.py: LLM-based content analysis  
- rule_engine.py: Rule-based content filtering

This modular approach provides better maintainability, testing, and extensibility.
"""

import os
import logging
import time
from typing import Dict, Any, Optional, List
from datetime import datetime
from dataclasses import dataclass
from collections import defaultdict

from .types import ChatMessage, PlatformClient, APIConfig
from .spam_detector import SpamDetector
from .llm_analyzer import LLMAnalyzer
from .rule_engine import RuleEngine

logger = logging.getLogger(__name__)


@dataclass
class ModerationResult:
    """Comprehensive moderation result from all modules."""
    action: str
    reason: str
    confidence: float
    timeout_seconds: int
    method: str
    processing_time: float
    details: Dict[str, Any]


class ModularChatModerationAgent:
    """
    Advanced modular chat moderation agent that orchestrates multiple specialized modules.
    """
    
    def __init__(
        self,
        platform_client: PlatformClient,
        api_key: Optional[str] = None,
        api_config: Optional[APIConfig] = None
    ):
        """
        Initialize the modular moderation agent.
        
        Args:
            platform_client: Client for platform-specific actions
            api_key: Gemini API key (optional)
            api_config: Optional APIConfig for advanced configuration
        """
        self.platform_client = platform_client
        
        # Initialize API configuration
        if api_config:
            self.api_config = api_config
        else:
            resolved_api_key = api_key or os.getenv("GEMINI_API_KEY")
            if not resolved_api_key:
                logger.warning("No API key provided. LLM functionality will be disabled.")
                resolved_api_key = ""
            
            self.api_config = APIConfig(api_key=resolved_api_key)
        
        # Initialize specialized modules
        self.spam_detector = SpamDetector()
        self.rule_engine = RuleEngine()
        
        # Initialize LLM analyzer only if API key is available
        if self.api_config.api_key:
            self.llm_analyzer = LLMAnalyzer(self.api_config)
            self.llm_available = True
        else:
            self.llm_analyzer = None
            self.llm_available = False
        
        # Statistics tracking
        self.total_messages_processed = 0
        self.actions_taken = defaultdict(int)
        # Initialize common actions
        self.actions_taken.update({
            'allow': 0,
            'remove': 0,
            'mute': 0,
            'timeout': 0,
            'warn': 0
        })
        self.methods_used = {
            'spam_detector': 0,
            'rule_engine': 0,
            'llm_analyzer': 0,
            'fallback': 0
        }
        
        logger.info(f"ModularChatModerationAgent initialized")
        logger.info(f"Modules loaded: SpamDetector, RuleEngine, LLMAnalyzer({self.llm_available})")
    
    def moderate_message(
        self,
        message: ChatMessage,
        rules: List[str] = None,
        execute_action: bool = True
    ) -> ModerationResult:
        """
        Main moderation function that orchestrates all modules.
        
        Args:
            message: ChatMessage to moderate
            rules: Optional list of community rules
            execute_action: Whether to execute the moderation action
            
        Returns:
            ModerationResult with comprehensive analysis
        """
        start_time = time.time()
        self.total_messages_processed += 1
        
        if rules is None:
            rules = []
        
        logger.info(f"Moderating message from {message.user_id}: {message.text[:100]}...")
        
        # Phase 1: Spam Detection (fastest, catches obvious spam)
        spam_result = self.spam_detector.detect_spam(message)
        if spam_result.is_spam:
            result = self._create_result_from_spam_detection(spam_result, start_time)
            self._track_and_execute(result, message, execute_action)
            return result
        
        # Phase 2: Rule Engine (fast, catches policy violations)
        rule_violation = self.rule_engine.check_message(message)
        if rule_violation:
            result = self._create_result_from_rule_violation(rule_violation, start_time)
            self._track_and_execute(result, message, execute_action)
            return result
        
        # Phase 3: LLM Analysis (slower, for ambiguous content)
        if self.llm_available and self.llm_analyzer:
            llm_result = self.llm_analyzer.analyze_message(message, rules)
            result = self._create_result_from_llm_analysis(llm_result, start_time)
            self._track_and_execute(result, message, execute_action)
            return result
        
        # Phase 4: Fallback (allow by default)
        result = self._create_fallback_result(start_time)
        self._track_and_execute(result, message, execute_action)
        return result
    
    def _create_result_from_spam_detection(self, spam_result, start_time: float) -> ModerationResult:
        """Create ModerationResult from spam detection."""
        action = "remove" if spam_result.is_spam else "allow"
        
        return ModerationResult(
            action=action,
            reason=spam_result.reason,
            confidence=spam_result.confidence,
            timeout_seconds=0,
            method="spam_detector",
            processing_time=time.time() - start_time,
            details={
                "spam_type": spam_result.spam_type,
                "spam_details": spam_result.details,
                "module": "spam_detector"
            }
        )
    
    def _create_result_from_rule_violation(self, violation, start_time: float) -> ModerationResult:
        """Create ModerationResult from rule violation."""
        return ModerationResult(
            action=violation.action,
            reason=violation.reason,
            confidence=violation.confidence,
            timeout_seconds=violation.timeout_seconds,
            method="rule_engine",
            processing_time=time.time() - start_time,
            details={
                "rule_type": violation.rule_type,
                "severity": violation.severity,
                "violation_details": violation.details,
                "module": "rule_engine"
            }
        )
    
    def _create_result_from_llm_analysis(self, llm_result, start_time: float) -> ModerationResult:
        """Create ModerationResult from LLM analysis."""
        return ModerationResult(
            action=llm_result.action,
            reason=llm_result.reason,
            confidence=llm_result.confidence,
            timeout_seconds=llm_result.timeout_seconds,
            method="llm_analyzer",
            processing_time=time.time() - start_time,
            details={
                "analysis_details": llm_result.analysis_details,
                "module": "llm_analyzer"
            }
        )
    
    def _create_fallback_result(self, start_time: float) -> ModerationResult:
        """Create fallback result when no issues detected."""
        return ModerationResult(
            action="allow",
            reason="No violations detected, message approved",
            confidence=0.5,
            timeout_seconds=0,
            method="fallback",
            processing_time=time.time() - start_time,
            details={
                "module": "fallback",
                "all_checks_passed": True
            }
        )
    
    def _track_and_execute(
        self,
        result: ModerationResult,
        message: ChatMessage,
        execute_action: bool
    ) -> None:
        """Track statistics and execute moderation action."""
        # Update statistics
        self.actions_taken[result.action] += 1
        self.methods_used[result.method] += 1
        
        # Execute action if requested
        if execute_action:
            self._execute_action(message, result)
        
        # Log result
        logger.info(
            f"Moderation complete: {result.action.upper()} - {result.reason} "
            f"({result.method}, {result.processing_time:.3f}s)"
        )
    
    def _execute_action(self, message: ChatMessage, result: ModerationResult) -> None:
        """Execute the moderation action using the platform client."""
        try:
            if result.action == "remove":
                self.platform_client.remove_message(message.id, message.channel_id)
            elif result.action == "mute":
                self.platform_client.mute_user(message.user_id, message.channel_id)
            elif result.action == "timeout":
                self.platform_client.timeout_user(
                    message.user_id, 
                    message.channel_id, 
                    result.timeout_seconds
                )
            # No action needed for "allow"
            
        except Exception as e:
            logger.error(f"Failed to execute {result.action} action: {e}")
    
    def check_health(self) -> Dict[str, Any]:
        """Check health of all modules."""
        health_status = {
            "overall_healthy": True,
            "modules": {}
        }
        
        # Check spam detector (always available)
        health_status["modules"]["spam_detector"] = {
            "healthy": True,
            "reason": "Spam detector operational"
        }
        
        # Check rule engine (always available)
        health_status["modules"]["rule_engine"] = {
            "healthy": True,
            "reason": "Rule engine operational"
        }
        
        # Check LLM analyzer (depends on API)
        if self.llm_analyzer:
            llm_health = self.llm_analyzer.check_health()
            health_status["modules"]["llm_analyzer"] = llm_health
            if not llm_health["healthy"]:
                health_status["overall_healthy"] = False
        else:
            health_status["modules"]["llm_analyzer"] = {
                "healthy": False,
                "reason": "No API key configured"
            }
        
        return health_status
    
    def get_comprehensive_stats(self) -> Dict[str, Any]:
        """Get comprehensive statistics from all modules."""
        stats = {
            "agent_stats": {
                "total_messages_processed": self.total_messages_processed,
                "actions_taken": dict(self.actions_taken),
                "methods_used": dict(self.methods_used),
                "llm_available": self.llm_available
            },
            "spam_detector_stats": self.spam_detector.get_stats(),
            "rule_engine_stats": self.rule_engine.get_stats(),
            "profanity_filter_stats": self.rule_engine.profanity_filter.get_stats()
        }
        
        if self.llm_analyzer:
            stats["llm_analyzer_stats"] = self.llm_analyzer.get_stats()
        
        return stats
    
    def configure_spam_detector(self, **kwargs) -> None:
        """Configure spam detector parameters."""
        self.spam_detector.update_config(**kwargs)
    
    def configure_rule_engine(self, **kwargs) -> None:
        """Configure rule engine parameters."""
        self.rule_engine.update_config(**kwargs)
    
    def add_custom_rule(self, rule: Dict[str, Any]) -> None:
        """Add a custom rule to the rule engine."""
        self.rule_engine.add_custom_rule(rule)
    
    def add_spam_keywords(self, category: str, keywords: List[str]) -> None:
        """Add spam keywords to the spam detector."""
        self.spam_detector.add_spam_keywords(category, keywords)
    
    def clear_user_data(self, user_id: Optional[str] = None) -> None:
        """Clear user data from all modules."""
        self.rule_engine.clear_user_data(user_id)
        logger.info(f"Cleared user data: {user_id or 'all users'}")
    
    def clear_caches(self) -> None:
        """Clear all caches."""
        if self.llm_analyzer:
            cache_size = self.llm_analyzer.clear_cache()
            logger.info(f"Cleared {cache_size} LLM cache entries")
    
    def get_user_profile(self, user_id: str) -> Dict[str, Any]:
        """Get comprehensive user profile from all modules."""
        return {
            "user_id": user_id,
            "rule_engine_stats": self.rule_engine.get_user_stats(user_id),
            "messages_processed": self.total_messages_processed,
            "timestamp": datetime.now().isoformat()
        }
    
    def add_profanity_words(self, severity: str, words: List[str]) -> None:
        """Add words to the profanity filter."""
        self.rule_engine.add_profanity_words(severity, words)
    
    def remove_profanity_words(self, severity: str, words: List[str]) -> None:
        """Remove words from the profanity filter."""
        self.rule_engine.remove_profanity_words(severity, words)
    
    def add_to_profanity_whitelist(self, words: List[str]) -> None:
        """Add words to the profanity filter whitelist."""
        self.rule_engine.add_to_profanity_whitelist(words)
    
    def test_profanity(self, text: str) -> Dict[str, Any]:
        """Test text for profanity (for debugging/admin purposes)."""
        return self.rule_engine.test_profanity(text)


# Backward compatibility alias
ChatModeratorAgent = ModularChatModerationAgent
