"""
Rule Engine Module

This module handles all rule-based content moderation including:
- Profanity and slur detection
- Flood/rate limiting detection
- User behavior tracking
- Custom rule matching
- Pattern-based filtering
"""

import re
import time
from typing import Dict, Any, Optional, List, Set
from dataclasses import dataclass
from collections import defaultdict, deque
from datetime import datetime, timedelta

from .types import ChatMessage
from .profanity_filter import ProfanityFilter


@dataclass
class RuleViolation:
    """Represents a rule violation."""
    rule_type: str
    severity: str  # 'low', 'medium', 'high', 'critical'
    action: str    # 'allow', 'warn', 'mute', 'remove', 'timeout'
    reason: str
    confidence: float
    timeout_seconds: int
    details: Dict[str, Any]


class RuleEngine:
    """
    Advanced rule-based content moderation engine.
    """
    
    def __init__(self):
        """Initialize the rule engine with default rules and patterns."""
        
        # Initialize advanced profanity filter
        self.profanity_filter = ProfanityFilter()
        
        # User behavior tracking
        self.user_message_history: Dict[str, deque] = defaultdict(lambda: deque(maxlen=20))
        self.user_warnings: Dict[str, int] = defaultdict(int)
        self.user_violations: Dict[str, List[RuleViolation]] = defaultdict(list)
        
        # Profanity and inappropriate content
        self.profanity_patterns = {
            'mild': [
                r'\b(damn|hell|crap|stupid|dumb|idiot|idiots)\b',
                r'\b(suck|sucks|lame)\b'
            ],
            'moderate': [
                r'\b(ass|asshole|bitch|bastard)\b',
                r'\b(shit|piss|fuck|fucking)\b'
            ],
            'severe': [
                r'\b(nigger|faggot|retard|cunt)\b',
                r'\b(kys|kill yourself)\b'
            ]
        }
        
        # Harassment patterns
        self.harassment_patterns = [
            r'\b(kill yourself|kys|die|suicide)\b',
            r'\b(you\s+(are|r)\s+(so|such)\s+(stupid|dumb|ugly|fat))\b',
            r'\b(nobody likes you|everyone hates you)\b',
            r'\b(go\s+(die|away|fuck yourself))\b'
        ]
        
        # Threat patterns
        self.threat_patterns = [
            r'\b(i\s+will\s+(kill|hurt|beat|destroy))\b',
            r'\b(gonna\s+(kill|hurt|beat|get))\s+you\b',
            r'\b(watch\s+your\s+back|you\s+better\s+watch)\b',
            r'\b(i\s+know\s+where\s+you\s+live)\b'
        ]
        
        # Spam indicators (used by spam_detector but also here for basic checks)
        self.basic_spam_words = {
            'buy', 'sell', 'cheap', 'free', 'win', 'prize', 'money', 'cash',
            'click', 'visit', 'website', 'link', 'promo', 'discount'
        }
        
        # Configuration
        self.flood_threshold = 5  # messages per time window
        self.flood_window = 30    # seconds
        self.caps_threshold = 0.7 # percentage of caps
        self.min_message_length = 3
        
        # Custom rules (can be added dynamically)
        self.custom_rules: List[Dict[str, Any]] = []
        
    def check_message(self, message: ChatMessage) -> Optional[RuleViolation]:
        """
        Check a message against all rules.
        
        Args:
            message: ChatMessage to check
            
        Returns:
            RuleViolation if any rule is violated, None otherwise
        """
        # Track user message
        self._track_user_message(message)
        
        # Check all rule types (ordered by severity)
        checks = [
            self._check_threats(message),
            self._check_harassment(message),
            self._check_advanced_profanity(message),  # New advanced profanity detection
            self._check_flooding(message),
            self._check_excessive_caps(message),
            self._check_basic_spam(message),
            self._check_custom_rules(message)
        ]
        
        # Return first violation found (highest severity)
        for violation in checks:
            if violation:
                self._record_violation(message.user_id, violation)
                return violation
        
        return None
    
    def _track_user_message(self, message: ChatMessage) -> None:
        """Track user message for behavior analysis."""
        self.user_message_history[message.user_id].append({
            'timestamp': time.time(),
            'message_id': message.id,
            'text': message.text,
            'channel_id': message.channel_id
        })
    
    def _record_violation(self, user_id: str, violation: RuleViolation) -> None:
        """Record a rule violation for a user."""
        self.user_violations[user_id].append(violation)
        
        # Escalate warnings
        if violation.action in ['warn', 'mute']:
            self.user_warnings[user_id] += 1
    
    def _check_threats(self, message: ChatMessage) -> Optional[RuleViolation]:
        """Check for threats and violent content."""
        text = message.text.lower()
        
        for pattern in self.threat_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                return RuleViolation(
                    rule_type='threats',
                    severity='critical',
                    action='timeout',
                    reason='Threatening language detected',
                    confidence=0.9,
                    timeout_seconds=3600,  # 1 hour
                    details={'pattern_matched': pattern, 'text_snippet': text[:100]}
                )
        
        return None
    
    def _check_harassment(self, message: ChatMessage) -> Optional[RuleViolation]:
        """Check for harassment and bullying."""
        text = message.text.lower()
        
        for pattern in self.harassment_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                # Check user's violation history for escalation
                warnings = self.user_warnings[message.user_id]
                
                if warnings >= 2:
                    action = 'timeout'
                    timeout_seconds = 1800  # 30 minutes
                elif warnings >= 1:
                    action = 'mute'
                    timeout_seconds = 0
                else:
                    action = 'remove'
                    timeout_seconds = 0
                
                return RuleViolation(
                    rule_type='harassment',
                    severity='high',
                    action=action,
                    reason='Harassment or bullying detected',
                    confidence=0.85,
                    timeout_seconds=timeout_seconds,
                    details={'pattern_matched': pattern, 'user_warnings': warnings}
                )
        
        return None
    
    def _check_advanced_profanity(self, message: ChatMessage) -> Optional[RuleViolation]:
        """Check for profanity using the advanced profanity filter."""
        profanity_result = self.profanity_filter.detect_profanity(message.text)
        
        if not profanity_result.is_profane:
            return None
        
        # Map profanity severity to rule violation severity and actions
        severity_mapping = {
            'extreme': {
                'rule_severity': 'critical',
                'action': 'timeout',
                'timeout_seconds': 7200,  # 2 hours
                'reason': 'Extremely inappropriate content detected'
            },
            'severe': {
                'rule_severity': 'high', 
                'action': 'remove',
                'timeout_seconds': 0,
                'reason': 'Severe inappropriate language detected'
            },
            'moderate': {
                'rule_severity': 'medium',
                'action': 'remove' if len(profanity_result.detected_words) > 2 else 'warn',
                'timeout_seconds': 0,
                'reason': 'Inappropriate language detected'
            },
            'mild': {
                'rule_severity': 'low',
                'action': 'warn',
                'timeout_seconds': 0,
                'reason': 'Mild inappropriate language detected'
            }
        }
        
        mapping = severity_mapping.get(profanity_result.severity, severity_mapping['mild'])
        
        # Escalate action based on user's violation history
        user_warnings = self.user_warnings[message.user_id]
        if user_warnings >= 2 and mapping['action'] == 'warn':
            mapping['action'] = 'timeout'
            mapping['timeout_seconds'] = 1800  # 30 minutes
        elif user_warnings >= 1 and mapping['action'] == 'warn':
            mapping['action'] = 'remove'
        
        return RuleViolation(
            rule_type=f'{profanity_result.severity}_profanity',
            severity=mapping['rule_severity'],
            action=mapping['action'],
            reason=f"{mapping['reason']}: {', '.join(profanity_result.detected_words[:3])}",
            confidence=profanity_result.confidence,
            timeout_seconds=mapping['timeout_seconds'],
            details={
                'detected_words': profanity_result.detected_words,
                'original_words': profanity_result.original_words,
                'profanity_severity': profanity_result.severity,
                'user_warnings': user_warnings,
                'filter_details': profanity_result.details
            }
        )
    
    def _check_flooding(self, message: ChatMessage) -> Optional[RuleViolation]:
        """Check for message flooding/spamming."""
        user_id = message.user_id
        current_time = time.time()
        
        # Get recent messages from this user
        recent_messages = [
            msg for msg in self.user_message_history[user_id]
            if current_time - msg['timestamp'] < self.flood_window
        ]
        
        if len(recent_messages) > self.flood_threshold:
            # Escalate based on violation history
            warnings = self.user_warnings[user_id]
            
            if warnings >= 2:
                action = 'timeout'
                timeout_seconds = 1800  # 30 minutes
                severity = 'high'
            elif warnings >= 1:
                action = 'timeout'
                timeout_seconds = 300   # 5 minutes
                severity = 'medium'
            else:
                action = 'mute'
                timeout_seconds = 0
                severity = 'medium'
            
            return RuleViolation(
                rule_type='flooding',
                severity=severity,
                action=action,
                reason=f'Message flooding detected ({len(recent_messages)} messages in {self.flood_window}s)',
                confidence=0.9,
                timeout_seconds=timeout_seconds,
                details={
                    'message_count': len(recent_messages),
                    'time_window': self.flood_window,
                    'user_warnings': warnings
                }
            )
        
        return None
    
    def _check_excessive_caps(self, message: ChatMessage) -> Optional[RuleViolation]:
        """Check for excessive capitalization."""
        text = message.text
        
        if len(text) < 10:  # Too short to analyze
            return None
        
        caps_count = sum(1 for c in text if c.isupper())
        caps_ratio = caps_count / len(text)
        
        if caps_ratio > self.caps_threshold:
            return RuleViolation(
                rule_type='excessive_caps',
                severity='low',
                action='warn',
                reason=f'Excessive capitalization ({caps_ratio:.1%} of message)',
                confidence=0.7,
                timeout_seconds=0,
                details={'caps_ratio': caps_ratio, 'threshold': self.caps_threshold}
            )
        
        return None
    
    def _check_basic_spam(self, message: ChatMessage) -> Optional[RuleViolation]:
        """Basic spam detection (more advanced spam detection in spam_detector.py)."""
        text = message.text.lower()
        words = set(text.split())
        
        # Check for multiple spam keywords
        spam_words_found = words.intersection(self.basic_spam_words)
        
        if len(spam_words_found) >= 3:  # Multiple spam indicators
            return RuleViolation(
                rule_type='basic_spam',
                severity='medium',
                action='remove',
                reason=f'Multiple spam indicators detected: {list(spam_words_found)}',
                confidence=0.7,
                timeout_seconds=0,
                details={'spam_words': list(spam_words_found)}
            )
        
        return None
    
    def _check_custom_rules(self, message: ChatMessage) -> Optional[RuleViolation]:
        """Check against custom rules."""
        for rule in self.custom_rules:
            if self._evaluate_custom_rule(message, rule):
                return RuleViolation(
                    rule_type='custom_rule',
                    severity=rule.get('severity', 'medium'),
                    action=rule.get('action', 'warn'),
                    reason=rule.get('reason', 'Custom rule violation'),
                    confidence=rule.get('confidence', 0.8),
                    timeout_seconds=rule.get('timeout_seconds', 0),
                    details={'rule_name': rule.get('name', 'unnamed'), 'rule_id': rule.get('id')}
                )
        
        return None
    
    def _evaluate_custom_rule(self, message: ChatMessage, rule: Dict[str, Any]) -> bool:
        """Evaluate a custom rule against a message."""
        rule_type = rule.get('type', 'pattern')
        
        if rule_type == 'pattern':
            pattern = rule.get('pattern', '')
            return bool(re.search(pattern, message.text, re.IGNORECASE))
        
        elif rule_type == 'keyword':
            keywords = rule.get('keywords', [])
            text_words = set(message.text.lower().split())
            return bool(text_words.intersection(set(keywords)))
        
        elif rule_type == 'length':
            min_length = rule.get('min_length', 0)
            max_length = rule.get('max_length', float('inf'))
            return not (min_length <= len(message.text) <= max_length)
        
        return False
    
    def add_custom_rule(self, rule: Dict[str, Any]) -> None:
        """Add a custom rule."""
        # Validate rule
        required_fields = ['type', 'action', 'reason']
        if not all(field in rule for field in required_fields):
            raise ValueError(f"Custom rule must contain: {required_fields}")
        
        # Add unique ID if not present
        if 'id' not in rule:
            rule['id'] = f"custom_{len(self.custom_rules)}"
        
        self.custom_rules.append(rule)
        print(f"Added custom rule: {rule.get('name', rule['id'])}")
    
    def remove_custom_rule(self, rule_id: str) -> bool:
        """Remove a custom rule by ID."""
        for i, rule in enumerate(self.custom_rules):
            if rule.get('id') == rule_id:
                removed_rule = self.custom_rules.pop(i)
                print(f"Removed custom rule: {removed_rule.get('name', rule_id)}")
                return True
        return False
    
    def get_user_stats(self, user_id: str) -> Dict[str, Any]:
        """Get statistics for a specific user."""
        return {
            'message_count': len(self.user_message_history[user_id]),
            'warnings': self.user_warnings[user_id],
            'violations': len(self.user_violations[user_id]),
            'recent_violations': [
                {
                    'type': v.rule_type,
                    'severity': v.severity,
                    'action': v.action,
                    'reason': v.reason
                }
                for v in self.user_violations[user_id][-5:]  # Last 5 violations
            ]
        }
    
    def clear_user_data(self, user_id: Optional[str] = None) -> None:
        """Clear user data."""
        if user_id:
            if user_id in self.user_message_history:
                del self.user_message_history[user_id]
            if user_id in self.user_warnings:
                del self.user_warnings[user_id]
            if user_id in self.user_violations:
                del self.user_violations[user_id]
        else:
            self.user_message_history.clear()
            self.user_warnings.clear()
            self.user_violations.clear()
    
    def get_stats(self) -> Dict[str, Any]:
        """Get rule engine statistics."""
        total_violations = sum(len(violations) for violations in self.user_violations.values())
        
        violation_types = defaultdict(int)
        for violations in self.user_violations.values():
            for violation in violations:
                violation_types[violation.rule_type] += 1
        
        return {
            'total_users_tracked': len(self.user_message_history),
            'total_warnings_issued': sum(self.user_warnings.values()),
            'total_violations': total_violations,
            'violation_types': dict(violation_types),
            'custom_rules_count': len(self.custom_rules),
            'config': {
                'flood_threshold': self.flood_threshold,
                'flood_window': self.flood_window,
                'caps_threshold': self.caps_threshold
            }
        }
    
    def update_config(self, **kwargs) -> None:
        """Update rule engine configuration."""
        for key, value in kwargs.items():
            if hasattr(self, key):
                setattr(self, key, value)
                print(f"Updated {key} = {value}")
            else:
                print(f"Unknown config parameter: {key}")
    
    def add_profanity_words(self, severity: str, words: List[str]) -> None:
        """Add words to the profanity filter."""
        self.profanity_filter.add_words(severity, words)
    
    def remove_profanity_words(self, severity: str, words: List[str]) -> None:
        """Remove words from the profanity filter."""
        self.profanity_filter.remove_words(severity, words)
    
    def add_to_profanity_whitelist(self, words: List[str]) -> None:
        """Add words to the profanity filter whitelist."""
        self.profanity_filter.add_to_whitelist(words)
    
    def test_profanity(self, text: str) -> Dict[str, Any]:
        """Test text for profanity (for debugging/admin purposes)."""
        result = self.profanity_filter.detect_profanity(text)
        return {
            'is_profane': result.is_profane,
            'severity': result.severity,
            'confidence': result.confidence,
            'detected_words': result.detected_words,
            'reason': result.reason
        }
