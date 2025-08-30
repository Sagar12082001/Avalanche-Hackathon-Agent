"""
Spam Detection Module

This module handles all spam-related detection including:
- Link spam detection
- Repetitive content detection
- ASCII art/wall detection
- Promotional content detection
- Excessive capitalization
"""

import re
from typing import Dict, Any, Optional
from dataclasses import dataclass
from datetime import datetime

from .types import ChatMessage


@dataclass
class SpamDetectionResult:
    """Result of spam detection analysis."""
    is_spam: bool
    spam_type: str
    confidence: float
    reason: str
    details: Dict[str, Any]


class SpamDetector:
    """
    Advanced spam detection engine with multiple detection methods.
    """
    
    def __init__(self):
        """Initialize the spam detector with configurable parameters."""
        
        # Spam keywords and patterns
        self.spam_keywords = {
            'promotional': {
                'buy', 'sell', 'cheap', 'discount', 'offer', 'deal', 'sale', 
                'money', 'cash', 'profit', 'earn', 'free', 'win', 'prize'
            },
            'scam': {
                'urgent', 'limited time', 'act now', 'click here', 'guarantee',
                'risk free', 'no questions asked', 'instant', 'miracle'
            },
            'crypto': {
                'bitcoin', 'crypto', 'nft', 'token', 'coin', 'trading',
                'investment', 'pump', 'moon', 'hodl'
            }
        }
        
        # Suspicious patterns
        self.suspicious_patterns = [
            r'https?://[^\s]+',  # URLs
            r'\b\d+%\s*(off|discount|profit)\b',  # Percentage offers
            r'\$\d+',  # Money amounts
            r'\b(call|text|dm)\s+me\b',  # Contact requests
            r'\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b',  # Phone numbers
        ]
        
        # Configuration
        self.max_links = 2
        self.max_caps_ratio = 0.6
        self.min_unique_word_ratio = 0.3
        self.max_special_char_ratio = 0.5
        
    def detect_spam(self, message: ChatMessage) -> SpamDetectionResult:
        """
        Main spam detection method that runs all checks.
        
        Args:
            message: ChatMessage to analyze
            
        Returns:
            SpamDetectionResult with detection details
        """
        text = message.text.lower().strip()
        
        # Run all detection methods
        link_spam = self._detect_link_spam(text)
        keyword_spam = self._detect_keyword_spam(text)
        repetitive_spam = self._detect_repetitive_content(text)
        caps_spam = self._detect_excessive_caps(message.text)
        ascii_spam = self._detect_ascii_walls(text)
        pattern_spam = self._detect_suspicious_patterns(text)
        
        # Combine results
        spam_checks = [link_spam, keyword_spam, repetitive_spam, caps_spam, ascii_spam, pattern_spam]
        spam_results = [check for check in spam_checks if check['is_spam']]
        
        if spam_results:
            # Find highest confidence result
            best_result = max(spam_results, key=lambda x: x['confidence'])
            
            return SpamDetectionResult(
                is_spam=True,
                spam_type=best_result['type'],
                confidence=best_result['confidence'],
                reason=best_result['reason'],
                details={
                    'all_detections': spam_results,
                    'message_length': len(message.text),
                    'word_count': len(text.split())
                }
            )
        
        return SpamDetectionResult(
            is_spam=False,
            spam_type='none',
            confidence=0.0,
            reason='No spam indicators detected',
            details={'checks_passed': len(spam_checks)}
        )
    
    def _detect_link_spam(self, text: str) -> Dict[str, Any]:
        """Detect excessive links or suspicious URLs."""
        urls = re.findall(r'https?://[^\s]+', text)
        
        if len(urls) > self.max_links:
            return {
                'is_spam': True,
                'type': 'link_spam',
                'confidence': min(0.9, 0.5 + (len(urls) - self.max_links) * 0.1),
                'reason': f'Too many links ({len(urls)} found, max {self.max_links})',
                'urls': urls
            }
        
        # Check for suspicious domains
        suspicious_domains = ['bit.ly', 'tinyurl', 'shorturl', 'scam', 'fake', 'virus', 'malware']
        for url in urls:
            for domain in suspicious_domains:
                if domain in url.lower():
                    return {
                        'is_spam': True,
                        'type': 'suspicious_link',
                        'confidence': 0.8,
                        'reason': f'Suspicious domain detected: {domain}',
                        'suspicious_url': url
                    }
        
        return {'is_spam': False, 'type': 'link_check', 'confidence': 0.0, 'reason': 'Links OK'}
    
    def _detect_keyword_spam(self, text: str) -> Dict[str, Any]:
        """Detect spam based on keyword patterns."""
        words = set(text.split())
        
        for category, keywords in self.spam_keywords.items():
            matches = words.intersection(keywords)
            if len(matches) >= 2:  # Multiple spam keywords
                return {
                    'is_spam': True,
                    'type': f'{category}_spam',
                    'confidence': min(0.9, 0.4 + len(matches) * 0.15),
                    'reason': f'Multiple {category} keywords detected: {list(matches)}',
                    'keywords': list(matches)
                }
        
        return {'is_spam': False, 'type': 'keyword_check', 'confidence': 0.0, 'reason': 'Keywords OK'}
    
    def _detect_repetitive_content(self, text: str) -> Dict[str, Any]:
        """Detect repetitive or low-quality content."""
        words = text.split()
        
        if len(words) < 3:
            return {'is_spam': False, 'type': 'repetition_check', 'confidence': 0.0, 'reason': 'Too short to analyze'}
        
        unique_words = set(words)
        unique_ratio = len(unique_words) / len(words)
        
        if unique_ratio < self.min_unique_word_ratio:
            return {
                'is_spam': True,
                'type': 'repetitive_spam',
                'confidence': 0.7 + (self.min_unique_word_ratio - unique_ratio),
                'reason': f'Highly repetitive content (unique ratio: {unique_ratio:.2f})',
                'unique_ratio': unique_ratio
            }
        
        # Check for repeated phrases
        if len(words) >= 6:
            for i in range(len(words) - 2):
                phrase = ' '.join(words[i:i+3])
                if text.count(phrase) >= 3:
                    return {
                        'is_spam': True,
                        'type': 'phrase_repetition',
                        'confidence': 0.8,
                        'reason': f'Repeated phrase detected: "{phrase}"',
                        'repeated_phrase': phrase
                    }
        
        return {'is_spam': False, 'type': 'repetition_check', 'confidence': 0.0, 'reason': 'Content variety OK'}
    
    def _detect_excessive_caps(self, text: str) -> Dict[str, Any]:
        """Detect excessive use of capital letters."""
        if len(text) < 10:
            return {'is_spam': False, 'type': 'caps_check', 'confidence': 0.0, 'reason': 'Too short for caps analysis'}
        
        caps_count = sum(1 for c in text if c.isupper())
        caps_ratio = caps_count / len(text)
        
        if caps_ratio > self.max_caps_ratio:
            return {
                'is_spam': True,
                'type': 'caps_spam',
                'confidence': min(0.9, 0.5 + (caps_ratio - self.max_caps_ratio)),
                'reason': f'Excessive capitalization ({caps_ratio:.1%} of text)',
                'caps_ratio': caps_ratio
            }
        
        return {'is_spam': False, 'type': 'caps_check', 'confidence': 0.0, 'reason': 'Capitalization OK'}
    
    def _detect_ascii_walls(self, text: str) -> Dict[str, Any]:
        """Detect ASCII art walls or excessive special characters."""
        if len(text) < 20:
            return {'is_spam': False, 'type': 'ascii_check', 'confidence': 0.0, 'reason': 'Too short for ASCII analysis'}
        
        special_chars = re.findall(r'[^a-zA-Z0-9\s]', text)
        special_ratio = len(special_chars) / len(text)
        
        if special_ratio > self.max_special_char_ratio:
            return {
                'is_spam': True,
                'type': 'ascii_wall',
                'confidence': min(0.9, 0.4 + special_ratio),
                'reason': f'Excessive special characters ({special_ratio:.1%} of text)',
                'special_ratio': special_ratio
            }
        
        # Check for common ASCII art patterns
        ascii_patterns = ['===', '---', '***', '+++', '^^^', '~~~']
        for pattern in ascii_patterns:
            if pattern * 3 in text:  # Pattern repeated 3+ times
                return {
                    'is_spam': True,
                    'type': 'ascii_art',
                    'confidence': 0.7,
                    'reason': f'ASCII art pattern detected: {pattern}',
                    'pattern': pattern
                }
        
        return {'is_spam': False, 'type': 'ascii_check', 'confidence': 0.0, 'reason': 'ASCII content OK'}
    
    def _detect_suspicious_patterns(self, text: str) -> Dict[str, Any]:
        """Detect suspicious patterns using regex."""
        for pattern in self.suspicious_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            if matches:
                # Different patterns have different spam likelihood
                if 'https?' in pattern and len(matches) > 2:
                    confidence = 0.6
                elif r'\$\d+' in pattern:
                    confidence = 0.7
                elif 'call|text|dm' in pattern:
                    confidence = 0.8
                else:
                    confidence = 0.5
                
                return {
                    'is_spam': True,
                    'type': 'pattern_match',
                    'confidence': confidence,
                    'reason': f'Suspicious pattern detected: {matches[0]}',
                    'matches': matches
                }
        
        return {'is_spam': False, 'type': 'pattern_check', 'confidence': 0.0, 'reason': 'No suspicious patterns'}
    
    def update_config(self, **kwargs) -> None:
        """Update spam detection configuration."""
        for key, value in kwargs.items():
            if hasattr(self, key):
                setattr(self, key, value)
                print(f"Updated {key} = {value}")
            else:
                print(f"Unknown config parameter: {key}")
    
    def add_spam_keywords(self, category: str, keywords: list) -> None:
        """Add new spam keywords to a category."""
        if category not in self.spam_keywords:
            self.spam_keywords[category] = set()
        
        self.spam_keywords[category].update(keywords)
        print(f"Added {len(keywords)} keywords to {category} category")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get spam detector statistics."""
        total_keywords = sum(len(keywords) for keywords in self.spam_keywords.values())
        
        return {
            'total_spam_keywords': total_keywords,
            'keyword_categories': list(self.spam_keywords.keys()),
            'suspicious_patterns': len(self.suspicious_patterns),
            'config': {
                'max_links': self.max_links,
                'max_caps_ratio': self.max_caps_ratio,
                'min_unique_word_ratio': self.min_unique_word_ratio,
                'max_special_char_ratio': self.max_special_char_ratio
            }
        }
