#!/usr/bin/env python3
"""
Command Line Interface for Chat Moderation Agent

Usage:
    python cli_moderator.py "Your message here"
    python cli_moderator.py --interactive
    python cli_moderator.py --help

Examples:
    python cli_moderator.py "Hello everyone!"
    python cli_moderator.py "Buy now! https://scam.com"
    python cli_moderator.py "You're an idiot!"
"""

import argparse
import sys
import os
from datetime import datetime
from mod_agent import ModularChatModerationAgent, ChatMessage, PlatformClient, APIConfig

# Fix Unicode encoding issues on Windows
if sys.platform.startswith('win'):
    import codecs
    sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer, 'strict')
    sys.stderr = codecs.getwriter('utf-8')(sys.stderr.buffer, 'strict')
    # Set console to UTF-8 mode
    os.system('chcp 65001 >nul 2>&1')


class CLIPlatformClient:
    """Simple platform client for CLI usage."""
    
    def remove_message(self, message_id: str, channel_id: str) -> bool:
        print(f"🗑️  [ACTION] Would remove message {message_id} from {channel_id}")
        return True
    
    def mute_user(self, user_id: str, channel_id: str) -> bool:
        print(f"🔇 [ACTION] Would mute user {user_id} in {channel_id}")
        return True
    
    def timeout_user(self, user_id: str, channel_id: str, seconds: int) -> bool:
        print(f"⏰ [ACTION] Would timeout user {user_id} in {channel_id} for {seconds}s")
        return True


def create_agent(api_key=None):
    """Create and configure the moderation agent."""
    platform_client = CLIPlatformClient()
    
    if api_key:
        api_config = APIConfig(api_key=api_key)
        agent = ModularChatModerationAgent(platform_client, api_config=api_config)
    else:
        agent = ModularChatModerationAgent(platform_client)
    
    return agent


def format_result(result, message_text):
    """Format the moderation result for display."""
    # Determine emoji based on action
    action_emojis = {
        'allow': '✅',
        'remove': '🚫', 
        'mute': '🔇',
        'timeout': '⏰'
    }
    
    emoji = action_emojis.get(result.action.lower(), '❓')
    
    print(f"\n📝 Message: \"{message_text}\"")
    print(f"{emoji} Result: {result.action.upper()}")
    print(f"📄 Reason: {result.reason}")
    print(f"🔧 Method: {result.method}")
    print(f"⏱️  Processing Time: {result.processing_time:.3f}s")
    
    if result.confidence:
        print(f"📊 Confidence: {result.confidence:.2f}")
    
    if result.timeout_seconds and result.timeout_seconds > 0:
        print(f"⏰ Timeout Duration: {result.timeout_seconds} seconds")


def moderate_single_message(agent, message_text, user_id="cli_user", channel_id="cli"):
    """Moderate a single message and display results."""
    # Create message object
    message = ChatMessage(
        id=f"cli_msg_{datetime.now().timestamp()}",
        user_id=user_id,
        text=message_text,
        timestamp=datetime.now(),
        channel_id=channel_id
    )
    
    # Default community rules
    rules = [
        "Keep discussions respectful and constructive",
        "No spam or promotional content", 
        "No personal attacks or harassment",
        "Maximum 2 links per message",
        "No excessive capitalization"
    ]
    
    # Moderate the message
    result = agent.moderate_message(message, rules)
    
    # Display results
    format_result(result, message_text)
    
    return result


def interactive_mode(agent):
    """Run in interactive mode for continuous testing."""
    print("🤖 Interactive Chat Moderation Mode")
    print("=" * 50)
    print("Enter messages to moderate them in real-time!")
    print("\nCommands:")
    print("  'stats' - Show agent statistics")
    print("  'health' - Check agent health") 
    print("  'test <text>' - Test specific text for profanity")
    print("  'help' - Show this help message")
    print("  'clear' - Clear the screen")
    print("  'quit', 'exit', or 'q' - Exit interactive mode")
    print("-" * 50)
    
    message_count = 0
    
    while True:
        try:
            # Get user input with a clean prompt
            print()  # Add spacing
            user_input = input("💬 Your message: ").strip()
            
            if not user_input:
                continue
                
            # Handle special commands
            command = user_input.lower()
            if command in ['quit', 'exit', 'q']:
                print("\n👋 Thanks for using the Chat Moderation Agent!")
                break
            elif command == 'stats':
                stats = agent.get_comprehensive_stats()
                print("\n📊 Agent Statistics:")
                agent_stats = stats['agent_stats']
                print(f"   Messages Processed: {agent_stats['total_messages_processed']}")
                print(f"   Actions Taken: {agent_stats['actions_taken']}")
                print(f"   Methods Used: {agent_stats['methods_used']}")
                print(f"   LLM Available: {agent_stats['llm_available']}")
                continue
            elif command == 'health':
                health = agent.check_health()
                print(f"\n🏥 Agent Health: {'Healthy' if health['overall_healthy'] else 'Limited'}")
                for module, status in health['modules'].items():
                    status_icon = "✅" if status['healthy'] else "⚠️"
                    print(f"   {status_icon} {module}: {status['reason']}")
                continue
            elif command.startswith('test '):
                # Test profanity detection on a specific word/phrase
                test_text = command[5:].strip()
                if test_text:
                    result = agent.test_profanity(test_text)
                    print(f"\n🧪 Profanity Test Results for: '{test_text}'")
                    print(f"   Is Profane: {'Yes' if result['is_profane'] else 'No'}")
                    if result['is_profane']:
                        print(f"   Severity: {result['severity'].title()}")
                        print(f"   Confidence: {result['confidence']:.2f}")
                        print(f"   Detected Words: {', '.join(result['detected_words'])}")
                        print(f"   Reason: {result['reason']}")
                else:
                    print("\n❌ Please provide text to test. Usage: test <text>")
                continue
            elif command == 'help':
                print("\n📖 Help:")
                print("   Just type any message to see how it would be moderated.")
                print("   The agent will analyze it and tell you if it should be allowed,")
                print("   removed, or if the user should be muted/timed out.")
                continue
            elif command == 'clear':
                os.system('cls' if os.name == 'nt' else 'clear')
                print("🤖 Interactive Chat Moderation Mode")
                print("=" * 50)
                continue
            
            # Moderate the message
            message_count += 1
            print(f"\n🔍 Analyzing message #{message_count}...")
            moderate_single_message(agent, user_input, f"user_{message_count}")
            
        except KeyboardInterrupt:
            print("\n\n👋 Interrupted by user. Goodbye!")
            break
        except Exception as e:
            print(f"\n❌ Error processing message: {e}")
            print("   Please try again or type 'quit' to exit.")


def main():
    """Main CLI function."""
    parser = argparse.ArgumentParser(
        description="Chat Moderation Agent CLI - Interactive Message Moderation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                                    # Start interactive mode (default)
  %(prog)s --interactive                      # Start interactive mode explicitly  
  %(prog)s "Hello everyone!"                  # Test single message
  %(prog)s --api-key YOUR_KEY "Test message"  # Test with AI analysis
        """
    )
    
    parser.add_argument(
        'message',
        nargs='?',
        help='Single message to moderate (if not provided, starts interactive mode)'
    )
    
    parser.add_argument(
        '-i', '--interactive',
        action='store_true',
        help='Run in interactive mode for continuous testing (default if no message provided)'
    )
    
    parser.add_argument(
        '--api-key',
        help='Gemini API key for LLM analysis (or set GEMINI_API_KEY env var)'
    )
    
    parser.add_argument(
        '--user-id',
        default='cli_user',
        help='User ID for the message (default: cli_user)'
    )
    
    parser.add_argument(
        '--channel-id', 
        default='cli',
        help='Channel ID for the message (default: cli)'
    )
    
    parser.add_argument(
        '--stats',
        action='store_true',
        help='Show agent statistics after moderation'
    )
    
    args = parser.parse_args()
    
    # Default to interactive mode if no message provided
    if not args.message and not args.interactive:
        args.interactive = True
    
    print("🤖 Chat Moderation Agent CLI")
    print("=" * 40)
    
    # Create agent
    try:
        agent = create_agent(args.api_key)
        
        # Check agent health
        health = agent.check_health()
        print(f"🏥 Agent Status: {'✅ Ready' if health['overall_healthy'] else '⚠️  Limited'}")
        
        if not health['overall_healthy']:
            print("💡 Note: Some modules unavailable, but basic moderation will work")
        
        if args.api_key or any('llm_analyzer' in str(v) and v.get('healthy') for v in health['modules'].values()):
            print("🧠 LLM Analysis: Enabled")
        else:
            print("🧠 LLM Analysis: Disabled (set --api-key or GEMINI_API_KEY for AI analysis)")
        
    except Exception as e:
        print(f"❌ Failed to initialize agent: {e}")
        sys.exit(1)
    
    # Run appropriate mode
    if args.interactive or not args.message:
        # Interactive mode (default)
        print("🎯 Starting interactive mode...")
        print("💡 Tip: You can also run single messages with: python cli_moderator.py \"your message\"")
        interactive_mode(agent)
    else:
        # Single message mode
        print("📝 Single message mode")
        result = moderate_single_message(agent, args.message, args.user_id, args.channel_id)
        
        # Show stats if requested
        if args.stats:
            stats = agent.get_comprehensive_stats()
            print(f"\n📊 Session Statistics:")
            agent_stats = stats['agent_stats']
            print(f"   Total Messages: {agent_stats['total_messages_processed']}")
            print(f"   Actions: {agent_stats['actions_taken']}")
            print(f"   Methods: {agent_stats['methods_used']}")


if __name__ == "__main__":
    main()
