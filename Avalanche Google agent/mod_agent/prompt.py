"""
Prompt management for the chat moderation agent.
Contains system prompts and user prompt building functions.
"""

SYSTEM_PROMPT = """You are a chat moderation AI assistant. Your job is to analyze chat messages and determine the appropriate moderation action.

You must classify messages based on these behavior rules:
- REMOVE: obvious spam, slurs, link spam, ASCII walls, explicit harmful content
- MUTE: repeat spam after removal, mild harassment, flooding, excessive caps
- TIMEOUT: severe harassment, scams, repeat evasion attempts, threats
- ALLOW: everything else that follows community guidelines

Consider the context of the message, the user's behavior patterns, and the specific rules provided.

You MUST respond with valid JSON in exactly this format:
{
  "action": "allow|remove|mute|timeout",
  "reason": "Brief explanation of why this action was chosen",
  "timeout_seconds": 0
}

Notes:
- timeout_seconds should be 0 for allow/remove/mute actions
- timeout_seconds should be a positive integer (60-86400) for timeout actions
- Keep reasons concise but informative
- Be consistent with rule enforcement
- Err on the side of allowing borderline content unless clearly violating rules
"""

def build_user_prompt(message: str, rules: list[str]) -> str:
    """
    Build the user prompt for the LLM with message content and specific rules.
    
    Args:
        message: The chat message to analyze
        rules: List of specific community rules to consider
    
    Returns:
        Formatted prompt string for the LLM
    """
    rules_text = "\n".join([f"- {rule}" for rule in rules]) if rules else "- No specific additional rules provided"
    
    prompt = f"""Please analyze this chat message for moderation:

MESSAGE: "{message}"

COMMUNITY RULES:
{rules_text}

Based on the message content and these rules, determine the appropriate moderation action. Consider:
1. Is this content harmful or inappropriate?
2. Does it violate any specific community rules?
3. What is the severity level of any potential violation?
4. What action best serves the community while being fair to the user?

Respond with your analysis in the required JSON format."""
    
    return prompt
