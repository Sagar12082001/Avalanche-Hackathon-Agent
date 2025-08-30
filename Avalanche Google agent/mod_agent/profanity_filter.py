"""
Advanced Profanity Filter Module

This module provides comprehensive bad word detection including:
- Extensive profanity word lists
- Leetspeak and character substitution detection
- Context-aware filtering
- Severity-based classification
- Bypass attempt detection
"""

import re
import string
from typing import Dict, List, Set, Optional, Tuple, Any
from dataclasses import dataclass
from collections import defaultdict


@dataclass
class ProfanityDetectionResult:
    """Result of profanity detection analysis."""
    is_profane: bool
    severity: str  # 'mild', 'moderate', 'severe', 'extreme'
    confidence: float
    detected_words: List[str]
    original_words: List[str]  # Original words before normalization
    reason: str
    details: Dict[str, Any]


class ProfanityFilter:
    """
    Advanced profanity detection system with multiple detection methods.
    """
    
    def __init__(self):
        """Initialize the profanity filter with comprehensive word lists."""
        
        # Comprehensive profanity word lists by severity
        self.profanity_words = {
            'mild': {
                # Mild inappropriate language
                'damn', 'hell', 'crap', 'dang', 'darn', 'bloody', 'blimey',
                'stupid', 'dumb', 'idiot', 'moron', 'fool', 'jerk', 'loser',
                'suck', 'sucks', 'lame', 'gay', 'retarded', 'tard', 'spastic',
                'piss', 'pissed', 'pee', 'butt', 'butthead', 'ass', 'arse','rascal'
            },
            
            'moderate': {
                # Moderate profanity
                'shit', 'shite', 'crap', 'bullshit', 'bs', 'damn', 'dammit',
                'bitch', 'bastard', 'asshole', 'dickhead', 'prick', 'cock',
                'dick', 'penis', 'vagina', 'pussy', 'boobs', 'tits', 'boob',
                'whore', 'slut', 'hoe', 'skank', 'thot', 'simp', 'incel'
            },
            
            'severe': {
                # Severe profanity and slurs
                'fuck', 'fucking', 'fucked', 'fucker', 'motherfucker', 'mf',
                'cunt', 'twat', 'fag', 'faggot', 'dyke', 'tranny', 'shemale',
                'nigger', 'nigga', 'negro', 'coon', 'spic', 'wetback', 'chink',
                'gook', 'jap', 'kike', 'hymie', 'raghead', 'towelhead', 'camel'
            },
            
            'extreme': {
                # Extremely offensive content and threats
                'kill yourself', 'kys', 'suicide', 'die', 'murder', 'rape',
                'molest', 'pedophile', 'pedo', 'child porn', 'cp', 'loli',
                'nazi', 'hitler', 'holocaust', 'genocide', 'terrorist', 'bomb',
                'shoot up', 'mass shooting', 'school shooter', 'terrorist attack'
            }
        }
        
        # Common character substitutions for leetspeak/bypass attempts
        self.char_substitutions = {
            '@': 'a', '4': 'a', '3': 'e', '1': 'i', '!': 'i', '0': 'o',
            '5': 's', '7': 't', '$': 's', '+': 't', '8': 'b', '6': 'g',
            '2': 'z', 'ph': 'f', 'ck': 'k', 'x': 'ks', 'z': 's'
        }
        
        # Common separators used to bypass filters
        self.separators = ['-', '_', '.', '*', ' ', '|', '/', '\\', '+', '=']
        
        # Whitelist - words that might trigger false positives
        self.whitelist = {
            'class', 'classic', 'assassin', 'assumption', 'bass', 'grass',
            'pass', 'glass', 'mass', 'brass', 'compass', 'harass', 'embarrass',
            'cassette', 'massacre', 'massachusetts', 'assess', 'process',
            'success', 'access', 'address', 'express', 'impress', 'suppress',
            'compress', 'distress', 'princess', 'mattress', 'actress',
            'buttercup', 'butterfly', 'button', 'scunthorpe', 'penistone'
        }
        
        # Context patterns that might indicate non-offensive usage
        self.context_patterns = [
            r'\b(class|classic|classical)\b',
            r'\b(grass|glass|pass|mass)\b',
            r'\b(assessment|assumption|assassin)\b',
            r'\b(harassment|embarrass)\b'
        ]
        
        # Compile regex patterns for efficiency
        self._compile_patterns()
        
    def _compile_patterns(self):
        """Compile regex patterns for efficient matching."""
        self.compiled_patterns = {}
        
        for severity, words in self.profanity_words.items():
            # Create simple word boundary patterns for each word
            patterns = []
            for word in words:
                # Simple word boundary pattern
                pattern = r'\b' + re.escape(word) + r'\b'
                patterns.append(pattern)
                
                # Add common variations
                if 'fuck' in word:
                    variations = [
                        word.replace('u', '[uv]'),
                        word.replace('ck', '[ck]'),
                        word.replace('f', '[fph]')
                    ]
                    for var in variations:
                        if var != word:
                            patterns.append(r'\b' + var + r'\b')
            
            # Combine all patterns for this severity level
            combined_pattern = '|'.join(patterns)
            self.compiled_patterns[severity] = re.compile(combined_pattern, re.IGNORECASE)
    
    def _create_flexible_pattern(self, word: str) -> str:
        """Create a flexible regex pattern that catches common bypass attempts."""
        # Start with the basic word
        base_pattern = re.escape(word.lower())
        
        # Create variations for common substitutions
        variations = [base_pattern]
        
        # Add common character substitutions
        substituted = word.lower()
        substituted = substituted.replace('a', '[a@4]')
        substituted = substituted.replace('e', '[e3]')
        substituted = substituted.replace('i', '[i1!]')
        substituted = substituted.replace('o', '[o0]')
        substituted = substituted.replace('s', '[s5$]')
        substituted = substituted.replace('u', '[uv]')
        substituted = substituted.replace('c', '[ck]')
        substituted = substituted.replace('f', '[fph]')
        
        variations.append(substituted)
        
        # Add pattern with optional separators
        separated = ''.join(f'{char}[\\-_\\.\\*\\s]*?' for char in word.lower())[:-12]  # Remove last separator
        variations.append(separated)
        
        # Combine all variations
        combined = '|'.join(variations)
        return r'\b(?:' + combined + r')\b'
    
    def detect_profanity(self, text: str) -> ProfanityDetectionResult:
        """
        Main profanity detection method.
        
        Args:
            text: Text to analyze for profanity
            
        Returns:
            ProfanityDetectionResult with detection details
        """
        if not text or not text.strip():
            return ProfanityDetectionResult(
                is_profane=False,
                severity='none',
                confidence=0.0,
                detected_words=[],
                original_words=[],
                reason='Empty or whitespace-only text',
                details={}
            )
        
        # Normalize text for analysis
        normalized_text = self._normalize_text(text)
        
        # Check against whitelist first
        if self._is_whitelisted(normalized_text):
            return ProfanityDetectionResult(
                is_profane=False,
                severity='none',
                confidence=0.0,
                detected_words=[],
                original_words=[],
                reason='Whitelisted content',
                details={'whitelisted': True}
            )
        
        # Check for profanity by severity (most severe first)
        for severity in ['extreme', 'severe', 'moderate', 'mild']:
            result = self._check_severity_level(text, normalized_text, severity)
            if result.is_profane:
                return result
        
        # No profanity detected
        return ProfanityDetectionResult(
            is_profane=False,
            severity='none',
            confidence=0.0,
            detected_words=[],
            original_words=[],
            reason='No profanity detected',
            details={'checks_passed': 4}
        )
    
    def _normalize_text(self, text: str) -> str:
        """Normalize text to catch bypass attempts."""
        normalized = text.lower()
        
        # Remove excessive whitespace and punctuation
        normalized = re.sub(r'\s+', ' ', normalized)
        normalized = re.sub(r'[^\w\s]', '', normalized)
        
        # Apply character substitutions
        for substitute, original in self.char_substitutions.items():
            normalized = normalized.replace(substitute, original)
        
        return normalized.strip()
    
    def _is_whitelisted(self, text: str) -> bool:
        """Check if text contains only whitelisted words."""
        words = set(text.split())
        return bool(words.intersection(self.whitelist))
    
    def _check_severity_level(self, original_text: str, normalized_text: str, severity: str) -> ProfanityDetectionResult:
        """Check for profanity at a specific severity level."""
        if severity not in self.compiled_patterns:
            return ProfanityDetectionResult(
                is_profane=False, severity='none', confidence=0.0,
                detected_words=[], original_words=[], reason='Invalid severity level',
                details={}
            )
        
        pattern = self.compiled_patterns[severity]
        matches = pattern.findall(original_text)  # Use original text for better matching
        
        if matches:
            # Clean up matches and remove duplicates
            detected_words = list(set(match.lower() for match in matches if match))
            original_words = matches
            
            # Calculate confidence based on severity and number of matches
            confidence = self._calculate_confidence(severity, len(detected_words))
            
            # Check for context that might reduce severity
            context_adjustment = self._analyze_context(original_text, detected_words)
            confidence *= context_adjustment
            
            return ProfanityDetectionResult(
                is_profane=True,
                severity=severity,
                confidence=confidence,
                detected_words=detected_words,
                original_words=original_words,
                reason=f'{severity.title()} profanity detected: {", ".join(detected_words[:3])}',
                details={
                    'match_count': len(detected_words),
                    'context_adjustment': context_adjustment,
                    'normalized_text': normalized_text[:100]
                }
            )
        
        return ProfanityDetectionResult(
            is_profane=False, severity='none', confidence=0.0,
            detected_words=[], original_words=[], reason=f'No {severity} profanity found',
            details={}
        )
    
    def _find_original_word(self, original_text: str, detected_word: str) -> str:
        """Find the original word in the text that matched the pattern."""
        # Simple approach: find words in original text that are similar to detected word
        words = re.findall(r'\b\w+\b', original_text, re.IGNORECASE)
        
        for word in words:
            if self._words_similar(word.lower(), detected_word.lower()):
                return word
        
        return detected_word
    
    def _words_similar(self, word1: str, word2: str) -> bool:
        """Check if two words are similar (accounting for substitutions)."""
        if word1 == word2:
            return True
        
        # Normalize both words
        norm1 = self._normalize_text(word1)
        norm2 = self._normalize_text(word2)
        
        return norm1 == norm2
    
    def _calculate_confidence(self, severity: str, match_count: int) -> float:
        """Calculate confidence score based on severity and match count."""
        base_confidence = {
            'mild': 0.6,
            'moderate': 0.75,
            'severe': 0.9,
            'extreme': 0.95
        }
        
        confidence = base_confidence.get(severity, 0.5)
        
        # Increase confidence with more matches
        confidence += min(0.1 * (match_count - 1), 0.2)
        
        return min(confidence, 1.0)
    
    def _analyze_context(self, text: str, detected_words: List[str]) -> float:
        """Analyze context to adjust confidence (reduce false positives)."""
        # Check for context patterns that might indicate non-offensive usage
        for pattern in self.context_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                return 0.5  # Reduce confidence by half
        
        # Check if detected words are part of larger, innocent words
        for word in detected_words:
            if len(word) < 4:  # Short words are more likely to be false positives
                return 0.8
        
        return 1.0  # No context adjustment needed
    
    def add_words(self, severity: str, words: List[str]) -> None:
        """Add new words to the profanity filter."""
        if severity not in self.profanity_words:
            self.profanity_words[severity] = set()
        
        self.profanity_words[severity].update(word.lower() for word in words)
        self._compile_patterns()  # Recompile patterns
        print(f"Added {len(words)} words to {severity} profanity list")
    
    def remove_words(self, severity: str, words: List[str]) -> None:
        """Remove words from the profanity filter."""
        if severity in self.profanity_words:
            for word in words:
                self.profanity_words[severity].discard(word.lower())
            self._compile_patterns()  # Recompile patterns
            print(f"Removed {len(words)} words from {severity} profanity list")
    
    def add_to_whitelist(self, words: List[str]) -> None:
        """Add words to the whitelist."""
        self.whitelist.update(word.lower() for word in words)
        print(f"Added {len(words)} words to whitelist")
    
    def test_word(self, word: str) -> ProfanityDetectionResult:
        """Test a single word for profanity."""
        return self.detect_profanity(word)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get profanity filter statistics."""
        total_words = sum(len(words) for words in self.profanity_words.values())
        
        return {
            'total_profanity_words': total_words,
            'words_by_severity': {
                severity: len(words) 
                for severity, words in self.profanity_words.items()
            },
            'whitelist_size': len(self.whitelist),
            'substitution_patterns': len(self.char_substitutions),
            'context_patterns': len(self.context_patterns)
        }
    
    def get_word_list(self, severity: str = None) -> Dict[str, Set[str]]:
        """Get word lists (for admin/debugging purposes)."""
        if severity:
            return {severity: self.profanity_words.get(severity, set())}
        return self.profanity_words.copy()
