"""
Chat Moderation Agent Module

A comprehensive modular chat moderation system using Google Generative AI
that combines specialized modules for different types of content analysis.

Key Components:
- ModularChatModerationAgent: Main orchestrating agent
- ChatMessage: Dataclass for representing chat messages  
- PlatformClient: Protocol for platform-specific moderation actions

Specialized Modules:
- SpamDetector: Advanced spam and promotional content detection
- LLMAnalyzer: AI-powered content analysis using Gemini
- RuleEngine: Rule-based filtering and user behavior tracking
"""

# Main modular agent (recommended)
from .modular_agent import ModularChatModerationAgent, ModerationResult

# Core types and data structures
from .types import ChatMessage, PlatformClient, APIConfig

# Specialized modules for advanced usage
from .spam_detector import SpamDetector, SpamDetectionResult
from .llm_analyzer import LLMAnalyzer, LLMAnalysisResult
from .rule_engine import RuleEngine, RuleViolation
from .profanity_filter import ProfanityFilter, ProfanityDetectionResult

# Backward compatibility
ChatModeratorAgent = ModularChatModerationAgent

__all__ = [
    # Main classes
    "ModularChatModerationAgent",
    "ChatModeratorAgent",  # Alias for backward compatibility
    "ChatMessage", 
    "PlatformClient",
    "APIConfig",
    
    # Result types
    "ModerationResult",
    "SpamDetectionResult",
    "LLMAnalysisResult", 
    "RuleViolation",
    "ProfanityDetectionResult",
    
    # Specialized modules
    "SpamDetector",
    "LLMAnalyzer",
    "RuleEngine",
    "ProfanityFilter"
]

__version__ = "2.0.0"
