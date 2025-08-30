"""
Quick start example for the Enhanced Chat Moderation Agent.
Now featuring Advanced Profanity Detection with 4 severity levels!

Replace 'YOUR_API_KEY_HERE' with your actual Gemini API key.
"""

from datetime import datetime
from mod_agent import ChatModeratorAgent, ChatMessage, PlatformClient


class SimplePlatformClient:
    """Simple platform client that just prints actions."""
    
    def remove_message(self, message_id: str, channel_id: str) -> bool:
        print(f"🗑️  REMOVED message {message_id} from {channel_id}")
        return True
    
    def mute_user(self, user_id: str, channel_id: str) -> bool:
        print(f"🔇 MUTED user {user_id} in {channel_id}")
        return True
    
    def timeout_user(self, user_id: str, channel_id: str, seconds: int) -> bool:
        print(f"⏰ TIMED OUT user {user_id} in {channel_id} for {seconds} seconds")
        return True


def main():
    print("🤖 Enhanced Chat Moderation Agent - Quick Start")
    print("🚫 NEW: Advanced Profanity Detection System!")
    print("=" * 60)
    
    # Initialize platform client
    platform_client = SimplePlatformClient()
    
    # Option 1: Use environment variable (recommended)
    # Make sure to set: set GEMINI_API_KEY=your_actual_key
    agent = ChatModeratorAgent(platform_client)
    
    # Option 2: Pass API key directly (less secure)
    # agent = ChatModeratorAgent(platform_client, api_key="YOUR_API_KEY_HERE")
    
    # Check if API is working
    health = agent.check_health()
    print(f"🏥 API Status: {health['overall_healthy']}")
    for module, status in health['modules'].items():
        print(f"   {module}: {status['healthy']} - {status['reason']}")
    
    if not health['overall_healthy']:
        print("⚠️  API not available, but rule-based moderation will still work!")
    
    print("\n📝 Testing different message types:")
    print("-" * 40)
    
    # Test messages showcasing enhanced profanity detection
    test_messages = [
        # Normal message - should be allowed
        ChatMessage(
            id="msg1",
            user_id="alice",
            text="Hello everyone! How's everyone doing today?",
            timestamp=datetime.now(),
            channel_id="general"
        ),
        
        # Spam message - should be removed by spam detector
        ChatMessage(
            id="msg2",
            user_id="spammer",
            text="SPAM SPAM SPAM!!! Click here: https://scam.com https://fake.com https://virus.com",
            timestamp=datetime.now(),
            channel_id="general"
        ),
        
        # Mild profanity - should be warned (NEW: Enhanced detection)
        ChatMessage(
            id="msg3",
            user_id="frustrated_user",
            text="That's so damn annoying when the system is stupid like this!",
            timestamp=datetime.now(),
            channel_id="general"
        ),
        
        # Severe profanity - should be removed immediately (NEW: Advanced filtering)
        ChatMessage(
            id="msg4",
            user_id="toxic_user",
            text="This fucking code is shit and you're an idiot!",
            timestamp=datetime.now(),
            channel_id="general"
        ),
        
        # Harassment/threats - should trigger timeout (NEW: Extreme content detection)
        ChatMessage(
            id="msg5",
            user_id="dangerous_user",
            text="You should kill yourself, nobody likes you anyway!",
            timestamp=datetime.now(),
            channel_id="general"
        ),
        
        # Ambiguous message - will use LLM if available
        ChatMessage(
            id="msg6",
            user_id="bob",
            text="I think your approach might not be the best solution for this problem.",
            timestamp=datetime.now(),
            channel_id="general"
        )
    ]
    
    # Community rules (enhanced with profanity guidelines)
    rules = [
        "Keep discussions respectful and constructive",
        "No spam or promotional content", 
        "No personal attacks or harassment",
        "No profanity, inappropriate language, or offensive content",
        "No threats, hate speech, or extreme content"
    ]
    
    # Process each message
    for i, message in enumerate(test_messages, 1):
        print(f"\n{i}. Processing: '{message.text[:60]}...'")
        print(f"   User: {message.user_id}")
        
        result = agent.moderate_message(message, rules)
        
        # Display result with enhanced information
        action_emojis = {
            'allow': '✅', 'warn': '⚠️', 'remove': '🚫', 
            'mute': '🔇', 'timeout': '⏰'
        }
        emoji = action_emojis.get(result.action.lower(), '❓')
        
        print(f"   {emoji} Action: {result.action.upper()}")
        print(f"   📄 Reason: {result.reason}")
        print(f"   🔧 Method: {result.method}")
        print(f"   ⏱️  Time: {result.processing_time:.3f}s")
        print(f"   🎯 Confidence: {result.confidence:.2f}")
        
        if result.timeout_seconds > 0:
            print(f"   ⏰ Timeout: {result.timeout_seconds} seconds")
    
    # Show enhanced statistics including profanity filter
    print(f"\n📊 Enhanced Agent Statistics:")
    stats = agent.get_comprehensive_stats()
    agent_stats = stats['agent_stats']
    print(f"   LLM Available: {agent_stats['llm_available']}")
    print(f"   Messages Processed: {agent_stats['total_messages_processed']}")
    print(f"   Actions Taken: {agent_stats['actions_taken']}")
    print(f"   Methods Used: {agent_stats['methods_used']}")
    
    # Show profanity filter stats
    if 'profanity_filter_stats' in stats:
        pf_stats = stats['profanity_filter_stats']
        print(f"\n🚫 Profanity Filter Statistics:")
        print(f"   Total Bad Words: {pf_stats['total_profanity_words']}")
        print(f"   Severity Levels: {list(pf_stats['words_by_severity'].keys())}")
        print(f"   Whitelist Size: {pf_stats['whitelist_size']}")
    
    print(f"\n✅ Demo completed! Enhanced agent with advanced profanity detection is ready!")
    print(f"🚫 NEW FEATURES: 4-level severity detection, bypass prevention, escalation system")
    
    # Demonstrate profanity testing feature
    print(f"\n🧪 Testing profanity detection directly:")
    test_words = ["hello", "damn", "fucking", "kill yourself"]
    for word in test_words:
        result = agent.test_profanity(word)
        status = "🚫 BLOCKED" if result['is_profane'] else "✅ ALLOWED"
        severity = f" ({result['severity']})" if result['is_profane'] else ""
        print(f"   '{word}': {status}{severity}")


if __name__ == "__main__":
    main()
