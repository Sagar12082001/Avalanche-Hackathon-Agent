# Chat Moderation Agent

A sophisticated chat moderation system that combines rule-based filtering with Google Generative AI for intelligent message analysis and moderation actions.

## Features

- **Rule-based filtering** for obvious violations (spam, slurs, flooding)
- **LLM-powered analysis** for ambiguous cases using Gemini 2.0 Flash via REST API
- **Flexible platform integration** via protocol-based design
- **Comprehensive action system**: allow, remove, mute, timeout
- **User behavior tracking** with warning escalation
- **Advanced API integration** with retry logic, rate limiting, and caching
- **Health monitoring** and diagnostics for API connectivity
- **Request caching** to reduce API calls and improve performance
- **Structured logging** for debugging and monitoring
- **Configuration management** with runtime updates
- **Graceful error handling** with fallback mechanisms

## Installation

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Set up your Gemini API key:
```bash
export GEMINI_API_KEY="your_api_key_here"
```

## Usage

### Basic Setup

```python
from mod_agent import ChatModeratorAgent, ChatMessage, PlatformClient
from mod_agent.agent import APIConfig
from datetime import datetime

# Implement your platform client
class MyPlatformClient:
    def remove_message(self, message_id: str, channel_id: str) -> bool:
        # Your implementation here
        return True
    
    def mute_user(self, user_id: str, channel_id: str) -> bool:
        # Your implementation here  
        return True
    
    def timeout_user(self, user_id: str, channel_id: str, seconds: int) -> bool:
        # Your implementation here
        return True

# Initialize the agent (uses GEMINI_API_KEY environment variable)
client = MyPlatformClient()
agent = ChatModeratorAgent(client)

# Process a message
message = ChatMessage(
    id="msg123",
    user_id="user456", 
    text="Some chat message text",
    timestamp=datetime.now(),
    channel_id="general"
)

rules = ["Keep discussions respectful and on-topic"]
result = agent.moderate_message(message, rules)
print(f"Action: {result['action']}")
print(f"Reason: {result['reason']}")
```

### Advanced Configuration

```python
from mod_agent.agent import APIConfig

# Create custom API configuration
api_config = APIConfig(
    api_key="your_api_key",
    model_name="gemini-2.0-flash",
    temperature=0.3,           # Response creativity (0.0-1.0)
    max_output_tokens=1024,    # Maximum response length
    timeout=30,                # Request timeout in seconds
    max_retries=3,             # Retry attempts for failed requests
    enable_caching=True,       # Enable response caching
    cache_ttl=300             # Cache time-to-live in seconds
)

agent = ChatModeratorAgent(client, api_config=api_config)

# Check API health
health = agent.check_api_health()
print(f"API Status: {health['healthy']} - {health['reason']}")

# Get agent statistics
stats = agent.get_stats()
print(f"Cache size: {stats['cache_size']}")
print(f"Users tracked: {stats['total_users_tracked']}")
```

### Running the Example

```bash
python example_usage.py
```

## API Integration Features

### Comprehensive Error Handling
- **Rate limiting**: Automatic retry with exponential backoff
- **Network failures**: Graceful degradation with fallback responses  
- **Invalid responses**: JSON parsing error recovery
- **Authentication errors**: Clear error messages and logging
- **API outages**: Health monitoring and status reporting

### Performance Optimization
- **Request caching**: Reduces API calls for similar messages
- **Configurable timeouts**: Prevent hanging requests
- **Retry logic**: Automatic retry with exponential backoff
- **Batch processing**: Efficient handling of multiple messages

### Monitoring & Management
- **Health checks**: Test API connectivity and authentication
- **Statistics tracking**: Monitor performance and usage
- **Structured logging**: Debug API interactions and errors
- **Configuration updates**: Runtime configuration changes
- **Cache management**: Control and clear cached responses

### Security & Reliability
- **Environment variable support**: Secure API key storage
- **Graceful fallbacks**: Continue operation during API failures
- **Input validation**: Sanitize and validate all inputs
- **Error isolation**: Prevent API failures from breaking moderation

## API Reference

### ChatModeratorAgent

Main moderation agent class with comprehensive API integration.

**Constructor:**
```python
ChatModeratorAgent(
    platform_client: PlatformClient,
    api_key: Optional[str] = None,
    api_config: Optional[APIConfig] = None
)
```

**Main Methods:**
- `moderate_message(message, rules=None, execute_action=True) -> Dict[str, Any]`
- `check_api_health() -> Dict[str, Any]`
- `get_stats() -> Dict[str, Any]`
- `clear_cache() -> None`
- `clear_user_data(user_id=None) -> None`
- `update_api_config(**kwargs) -> None`

### APIConfig

Configuration class for advanced API settings.

**Parameters:**
- `api_key: str` - Gemini API key
- `model_name: str` - Model name (default: "gemini-2.0-flash")
- `temperature: float` - Response creativity 0.0-1.0 (default: 0.3)
- `max_output_tokens: int` - Maximum response length (default: 1024)
- `timeout: int` - Request timeout in seconds (default: 30)
- `max_retries: int` - Retry attempts (default: 3)
- `enable_caching: bool` - Enable response caching (default: True)
- `cache_ttl: int` - Cache time-to-live in seconds (default: 300)

### ChatMessage

Dataclass representing a chat message.

**Fields:**
- `id: str` - Unique message identifier
- `user_id: str` - User who sent the message
- `text: str` - Message content
- `timestamp: datetime` - When message was sent
- `channel_id: str` - Channel where message was sent

### PlatformClient

Protocol defining platform-specific moderation actions.

**Methods:**
- `remove_message(message_id: str, channel_id: str) -> bool`
- `mute_user(user_id: str, channel_id: str) -> bool` 
- `timeout_user(user_id: str, channel_id: str, seconds: int) -> bool`

## Moderation Rules

The agent follows these behavior rules:

- **REMOVE**: Obvious spam, slurs, link spam, ASCII walls
- **MUTE**: Repeat spam after removal, mild harassment, flooding
- **TIMEOUT**: Severe harassment, scams, repeat evasion
- **ALLOW**: Everything else that follows community guidelines

## Error Handling

The agent gracefully handles:
- Missing or invalid Gemini API keys
- Network failures when querying the LLM
- Invalid or malformed model responses
- Platform client action failures

In error cases, it defaults to allowing content while logging warnings.
