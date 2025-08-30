"""
Core types and data structures for the chat moderation system.
Contains the essential classes used across all modules.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Protocol, Dict, Any


class PlatformClient(Protocol):
    """Protocol defining the interface for platform-specific moderation actions."""
    
    def remove_message(self, message_id: str, channel_id: str) -> bool:
        """Remove a message from the platform."""
        ...
    
    def mute_user(self, user_id: str, channel_id: str) -> bool:
        """Mute a user in the specified channel."""
        ...
    
    def timeout_user(self, user_id: str, channel_id: str, seconds: int) -> bool:
        """Timeout a user for the specified duration in seconds."""
        ...


@dataclass
class ChatMessage:
    """Represents a chat message with all necessary metadata."""
    
    id: str
    user_id: str
    text: str
    timestamp: datetime
    channel_id: str


@dataclass
class APIConfig:
    """Configuration for Gemini API calls."""
    
    api_key: str
    model_name: str = "gemini-2.0-flash"
    base_url: str = "https://generativelanguage.googleapis.com/v1beta"
    temperature: float = 0.3
    max_output_tokens: int = 1024
    timeout: int = 30
    max_retries: int = 3
    retry_delay: float = 1.0
    enable_caching: bool = True
    cache_ttl: int = 300  # 5 minutes


@dataclass 
class CacheEntry:
    """Cache entry for API responses."""
    
    response: Dict[str, Any]
    timestamp: datetime
    ttl: int = 300
