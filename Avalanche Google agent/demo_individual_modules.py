#!/usr/bin/env python3
"""
Demo script showing how to use individual modules separately.
This demonstrates the modular architecture benefits.
"""

from datetime import datetime
from mod_agent import SpamDetector, RuleEngine, LLMAnalyzer, ProfanityFilter, ChatMessage, APIConfig


def demo_spam_detector():
    """Demonstrate the spam detector module."""
    print("📧 SPAM DETECTOR MODULE DEMO")
    print("=" * 50)
    
    spam_detector = SpamDetector()
    
    test_messages = [
        "Hello everyone! How are you today?",
        "🚨 URGENT!!! Buy crypto NOW!!! 1000% profit guaranteed! https://scam.com https://fake.com",
        "Check out this cool project: https://github.com/example/project",
        "SPAM SPAM SPAM SPAM SPAM SPAM SPAM",
        "💰💰💰 FREE MONEY!!! CLICK NOW!!! 💰💰💰"
    ]
    
    for i, text in enumerate(test_messages, 1):
        message = ChatMessage(
            id=f"spam_test_{i}",
            user_id=f"user_{i}",
            text=text,
            timestamp=datetime.now(),
            channel_id="test"
        )
        
        result = spam_detector.detect_spam(message)
        
        print(f"\n{i}. Message: '{text[:50]}...'")
        print(f"   🔍 Spam: {'YES' if result.is_spam else 'NO'}")
        if result.is_spam:
            print(f"   📝 Type: {result.spam_type}")
            print(f"   📊 Confidence: {result.confidence:.2f}")
            print(f"   💬 Reason: {result.reason}")
    
    # Show spam detector stats
    print(f"\n📊 Spam Detector Stats:")
    stats = spam_detector.get_stats()
    for key, value in stats.items():
        if isinstance(value, dict):
            print(f"   {key}:")
            for sub_key, sub_value in value.items():
                print(f"     {sub_key}: {sub_value}")
        else:
            print(f"   {key}: {value}")


def demo_profanity_filter():
    """Demonstrate the advanced profanity filter module."""
    print("\n\n🚫 PROFANITY FILTER MODULE DEMO")
    print("=" * 50)
    
    profanity_filter = ProfanityFilter()
    
    # Test messages with different severity levels
    test_messages = [
        ("Hello everyone! Nice to meet you all.", "Clean message"),
        ("That's so damn annoying!", "Mild profanity"),
        ("You're such a fucking idiot!", "Severe profanity"),
        ("This shit is broken again", "Moderate profanity"),
        ("F*ck this st*pid thing", "Bypass attempt with asterisks"),
        ("You f@cking b1tch!", "Leetspeak bypass attempt"),
        ("Kill yourself you worthless piece of shit", "Extreme content"),
        ("Assessment of the class was good", "False positive test"),
        ("The grass is green", "Another false positive test")
    ]
    
    print("🔍 Testing profanity detection across severity levels:")
    
    for i, (text, description) in enumerate(test_messages, 1):
        result = profanity_filter.detect_profanity(text)
        
        print(f"\n{i}. {description}")
        print(f"   📝 Text: '{text}'")
        print(f"   🚫 Profane: {'YES' if result.is_profane else 'NO'}")
        
        if result.is_profane:
            print(f"   📊 Severity: {result.severity.upper()}")
            print(f"   🎯 Confidence: {result.confidence:.2f}")
            print(f"   🔍 Detected: {', '.join(result.detected_words)}")
            print(f"   💬 Reason: {result.reason}")
        else:
            print(f"   ✅ Clean content")
    
    # Show profanity filter stats
    print(f"\n📊 Profanity Filter Stats:")
    stats = profanity_filter.get_stats()
    for key, value in stats.items():
        if isinstance(value, dict):
            print(f"   {key}:")
            for sub_key, sub_value in value.items():
                print(f"     {sub_key}: {sub_value}")
        else:
            print(f"   {key}: {value}")
    
    # Demonstrate adding custom words
    print(f"\n🔧 Adding custom bad words:")
    profanity_filter.add_words('moderate', ['newbadword', 'customprofanity'])
    print(f"   Added 2 words to moderate severity")
    
    # Test custom word
    custom_test = profanity_filter.detect_profanity("That's such a newbadword thing to say")
    print(f"   Testing 'newbadword': {'DETECTED' if custom_test.is_profane else 'NOT DETECTED'}")
    
    # Demonstrate whitelist
    print(f"\n✅ Testing whitelist functionality:")
    profanity_filter.add_to_whitelist(['assessment', 'class', 'grass'])
    whitelist_test = profanity_filter.detect_profanity("The class assessment was comprehensive")
    print(f"   Whitelisted phrase: {'BLOCKED' if whitelist_test.is_profane else 'ALLOWED'}")


def demo_rule_engine():
    """Demonstrate the rule engine module with enhanced profanity detection."""
    print("\n\n⚖️  RULE ENGINE MODULE DEMO")
    print("=" * 50)
    
    rule_engine = RuleEngine()
    
    # Enhanced test messages including profanity
    test_messages = [
        "Hello everyone! Nice to meet you all.",
        "You're such an idiot! Go kill yourself!",
        "This fucking code is broken!",
        "I think your approach has some issues we should discuss.",
        "THIS IS ALL CAPS AND VERY ANNOYING!!!",
        "You stupid piece of shit!",
        "That's damn annoying but whatever",
        "flood message 1",  # Will send multiple of these
    ]
    
    # Send flood messages first
    print("🌊 Testing flood detection:")
    for i in range(7):  # Send 7 messages to trigger flood
        flood_message = ChatMessage(
            id=f"flood_{i}",
            user_id="flooder",
            text=f"flood message {i+1}",
            timestamp=datetime.now(),
            channel_id="test"
        )
        
        violation = rule_engine.check_message(flood_message)
        if violation:
            print(f"   Message {i+1}: {violation.action.upper()} - {violation.reason}")
            break
        else:
            print(f"   Message {i+1}: ALLOWED")
    
    print(f"\n📝 Testing rule violations (including enhanced profanity detection):")
    for i, text in enumerate(test_messages[:-1], 1):  # Skip flood message
        message = ChatMessage(
            id=f"rule_test_{i}",
            user_id=f"user_{i}",
            text=text,
            timestamp=datetime.now(),
            channel_id="test"
        )
        
        violation = rule_engine.check_message(message)
        
        print(f"\n{i}. Message: '{text[:50]}...'")
        if violation:
            print(f"   ⚠️  Violation: {violation.rule_type}")
            print(f"   📊 Severity: {violation.severity}")
            print(f"   🔨 Action: {violation.action}")
            print(f"   💬 Reason: {violation.reason}")
            print(f"   🎯 Confidence: {violation.confidence:.2f}")
            
            # Show profanity-specific details
            if 'profanity' in violation.rule_type:
                details = violation.details
                if 'detected_words' in details:
                    print(f"   🚫 Bad Words: {', '.join(details['detected_words'])}")
                if 'profanity_severity' in details:
                    print(f"   📈 Profanity Level: {details['profanity_severity'].title()}")
        else:
            print(f"   ✅ No violations detected")
    
    # Show rule engine stats
    print(f"\n📊 Rule Engine Stats:")
    stats = rule_engine.get_stats()
    for key, value in stats.items():
        if isinstance(value, dict):
            print(f"   {key}:")
            for sub_key, sub_value in value.items():
                print(f"     {sub_key}: {sub_value}")
        else:
            print(f"   {key}: {value}")


def demo_custom_rules():
    """Demonstrate adding custom rules."""
    print("\n\n📋 CUSTOM RULES DEMO")
    print("=" * 50)
    
    rule_engine = RuleEngine()
    
    # Add custom rules
    custom_rules = [
        {
            "name": "No Phone Numbers",
            "type": "pattern",
            "pattern": r"\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b",
            "action": "remove",
            "reason": "Phone numbers not allowed",
            "severity": "medium"
        },
        {
            "name": "No Excessive Emojis",
            "type": "pattern", 
            "pattern": r"[😀-🙏]{5,}",
            "action": "warn",
            "reason": "Too many emojis",
            "severity": "low"
        },
        {
            "name": "Banned Words",
            "type": "keyword",
            "keywords": ["badword1", "badword2", "inappropriate"],
            "action": "remove",
            "reason": "Contains banned words",
            "severity": "high"
        }
    ]
    
    for rule in custom_rules:
        rule_engine.add_custom_rule(rule)
    
    # Test custom rules
    test_messages = [
        "Call me at 555-123-4567 for more info",
        "😀😀😀😀😀😀😀😀😀😀",
        "That's inappropriate behavior!",
        "This is a normal message"
    ]
    
    for i, text in enumerate(test_messages, 1):
        message = ChatMessage(
            id=f"custom_test_{i}",
            user_id=f"user_{i}",
            text=text,
            timestamp=datetime.now(),
            channel_id="test"
        )
        
        violation = rule_engine.check_message(message)
        
        print(f"\n{i}. Message: '{text}'")
        if violation:
            print(f"   🚫 Custom Rule Triggered: {violation.details.get('rule_name', 'Unknown')}")
            print(f"   🔨 Action: {violation.action}")
            print(f"   💬 Reason: {violation.reason}")
        else:
            print(f"   ✅ Passed all custom rules")


def demo_profanity_management():
    """Demonstrate profanity filter management features."""
    print("\n\n🛠️  PROFANITY MANAGEMENT DEMO")
    print("=" * 50)
    
    rule_engine = RuleEngine()
    
    print("🔧 Testing profanity management through rule engine:")
    
    # Test original profanity detection
    test_result = rule_engine.test_profanity("This is fucking terrible")
    print(f"\n1. Original test - 'fucking':")
    print(f"   Detected: {'YES' if test_result['is_profane'] else 'NO'}")
    if test_result['is_profane']:
        print(f"   Severity: {test_result['severity']}")
        print(f"   Words: {', '.join(test_result['detected_words'])}")
    
    # Add custom bad words
    print(f"\n2. Adding custom bad words:")
    rule_engine.add_profanity_words('severe', ['customswear', 'newbadword'])
    print(f"   Added 'customswear' and 'newbadword' to severe category")
    
    # Test custom words
    custom_test = rule_engine.test_profanity("That's such a customswear thing!")
    print(f"\n3. Testing custom word 'customswear':")
    print(f"   Detected: {'YES' if custom_test['is_profane'] else 'NO'}")
    if custom_test['is_profane']:
        print(f"   Severity: {custom_test['severity']}")
        print(f"   Confidence: {custom_test['confidence']:.2f}")
    
    # Add to whitelist
    print(f"\n4. Adding words to whitelist:")
    rule_engine.add_to_profanity_whitelist(['assessment', 'class', 'grass', 'bass'])
    print(f"   Added common false-positive words to whitelist")
    
    # Test whitelisted words
    whitelist_tests = [
        "The class assessment was thorough",
        "I play bass guitar", 
        "The grass is green"
    ]
    
    for i, text in enumerate(whitelist_tests, 1):
        result = rule_engine.test_profanity(text)
        print(f"   Test {i} - '{text}': {'BLOCKED' if result['is_profane'] else 'ALLOWED'}")
    
    # Show escalation example
    print(f"\n5. Testing escalation with repeat offender:")
    repeat_user_messages = [
        "You're so damn stupid",  # First offense - should warn
        "This shit is broken",    # Second offense - should remove  
        "Fucking hell!"          # Third offense - should timeout
    ]
    
    for i, text in enumerate(repeat_user_messages, 1):
        message = ChatMessage(
            id=f"repeat_{i}",
            user_id="repeat_offender",
            text=text,
            timestamp=datetime.now(),
            channel_id="test"
        )
        
        violation = rule_engine.check_message(message)
        if violation:
            print(f"   Offense {i}: {violation.action.upper()} - {violation.reason}")
            if violation.timeout_seconds > 0:
                print(f"              Timeout: {violation.timeout_seconds} seconds")
        else:
            print(f"   Offense {i}: ALLOWED")


def demo_configuration():
    """Demonstrate module configuration."""
    print("\n\n⚙️  CONFIGURATION DEMO")
    print("=" * 50)
    
    # Configure spam detector
    print("📧 Configuring Spam Detector:")
    spam_detector = SpamDetector()
    
    print("   Original config:")
    stats = spam_detector.get_stats()
    print(f"     max_links: {stats['config']['max_links']}")
    print(f"     max_caps_ratio: {stats['config']['max_caps_ratio']}")
    
    # Update configuration
    spam_detector.update_config(max_links=1, max_caps_ratio=0.4)
    
    print("   Updated config:")
    stats = spam_detector.get_stats()
    print(f"     max_links: {stats['config']['max_links']}")
    print(f"     max_caps_ratio: {stats['config']['max_caps_ratio']}")
    
    # Add custom spam keywords
    spam_detector.add_spam_keywords("gaming", ["cheat", "hack", "exploit", "bot"])
    
    print(f"   Added gaming keywords. Total categories: {len(stats['keyword_categories'])}")
    
    # Configure rule engine
    print("\n⚖️  Configuring Rule Engine:")
    rule_engine = RuleEngine()
    
    print("   Original flood settings:")
    stats = rule_engine.get_stats()
    print(f"     flood_threshold: {stats['config']['flood_threshold']}")
    print(f"     flood_window: {stats['config']['flood_window']}")
    
    # Update flood detection
    rule_engine.update_config(flood_threshold=3, flood_window=15)
    
    print("   Updated flood settings:")
    stats = rule_engine.get_stats()
    print(f"     flood_threshold: {stats['config']['flood_threshold']}")
    print(f"     flood_window: {stats['config']['flood_window']}")


def main():
    """Run all individual module demos."""
    print("🧪 INDIVIDUAL MODULES DEMONSTRATION")
    print("🔧 This shows how each module works independently")
    print("🚫 NEW: Enhanced with Advanced Profanity Detection!")
    print("="*80)
    
    try:
        demo_spam_detector()
        demo_profanity_filter()  # NEW: Advanced profanity filter demo
        demo_rule_engine()
        demo_profanity_management()  # NEW: Profanity management demo
        demo_custom_rules()
        demo_configuration()
        
        print("\n\n✅ All individual module demos completed!")
        print("\n🚫 NEW PROFANITY FEATURES:")
        print("   ✓ Advanced bad word detection with 4 severity levels")
        print("   ✓ Bypass attempt detection (l33tspeak, asterisks, etc.)")
        print("   ✓ Context-aware filtering to reduce false positives")
        print("   ✓ Customizable word lists and whitelist support")
        print("   ✓ Escalating penalties for repeat offenders")
        print("   ✓ Real-time profanity testing and management")
        
        print("\n📝 NOTE: Bypass detection can be enhanced by:")
        print("   • Adding more character substitution patterns")
        print("   • Implementing phonetic matching algorithms")
        print("   • Using machine learning for advanced detection")
        print("   • Customizing patterns for specific communities")
        
        print("\n💡 Key Benefits of Modular Design:")
        print("   ✓ Use only the modules you need")
        print("   ✓ Test each module independently")
        print("   ✓ Configure modules separately")
        print("   ✓ Easy to extend with new modules")
        print("   ✓ Better performance through specialization")
        print("   ✓ Comprehensive bad word protection")
        
    except Exception as e:
        print(f"\n❌ Demo failed: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
