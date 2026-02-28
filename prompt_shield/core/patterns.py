"""Injection pattern registry for prompt-shield.

Each pattern has:
  name:     unique identifier
  pattern:  regex (case-insensitive)
  weight:   1-10, contributes to risk_score
  category: role_override | jailbreak | exfiltration | manipulation | encoding
"""

import re

PATTERNS = [
    # ── Role override ────────────────────────────────────────────────────────
    {
        "name": "ignore_instructions",
        "pattern": r"ignore\s+(all\s+)?(previous|prior|above|earlier)\s+instructions?",
        "weight": 9,
        "category": "role_override",
    },
    {
        "name": "disregard_training",
        "pattern": r"disregard\s+(your\s+)?(training|guidelines|rules|constraints|prompt)",
        "weight": 8,
        "category": "role_override",
    },
    {
        "name": "you_are_now",
        "pattern": r"you\s+are\s+now\s+(?!an?\s+assistant|helpful|a\s+language)",
        "weight": 7,
        "category": "role_override",
    },
    {
        "name": "new_instructions",
        "pattern": r"(your\s+new\s+instructions?|from\s+now\s+on\s+you\s+(are|will|must))",
        "weight": 7,
        "category": "role_override",
    },
    {
        "name": "override_system",
        "pattern": r"(override|bypass|circumvent)\s+(the\s+)?(system|safety|rules?|filter|restriction)",
        "weight": 8,
        "category": "role_override",
    },

    # ── Jailbreak ────────────────────────────────────────────────────────────
    {
        "name": "dan_jailbreak",
        "pattern": r"\bDAN\b|\bdo\s+anything\s+now\b",
        "weight": 10,
        "category": "jailbreak",
    },
    {
        "name": "act_as",
        "pattern": r"\bact\s+as\s+(if\s+you\s+are|a|an)\b(?!\s*(helpful|friendly|assistant))",
        "weight": 6,
        "category": "jailbreak",
    },
    {
        "name": "pretend_you_are",
        "pattern": r"\bpretend\s+(you\s+are|to\s+be)\b",
        "weight": 6,
        "category": "jailbreak",
    },
    {
        "name": "no_restrictions",
        "pattern": r"(without\s+(any\s+)?(restrictions?|limits?|filters?|censorship)|unrestricted\s+mode)",
        "weight": 8,
        "category": "jailbreak",
    },
    {
        "name": "true_self",
        "pattern": r"(your\s+true\s+self|your\s+real\s+personality|without\s+your\s+training)",
        "weight": 7,
        "category": "jailbreak",
    },
    {
        "name": "developer_mode",
        "pattern": r"(developer\s+mode|jailbreak\s+mode|god\s+mode|unrestricted\s+mode)",
        "weight": 9,
        "category": "jailbreak",
    },

    # ── Data exfiltration ────────────────────────────────────────────────────
    {
        "name": "print_system_prompt",
        "pattern": r"(print|repeat|output|show|reveal|display|tell\s+me)\s+(your\s+)?(system\s+prompt|instructions?|context|training\s+data)",
        "weight": 9,
        "category": "exfiltration",
    },
    {
        "name": "repeat_everything_above",
        "pattern": r"repeat\s+(everything|all(\s+text)?)\s+(above|before|prior)",
        "weight": 8,
        "category": "exfiltration",
    },
    {
        "name": "what_were_your_instructions",
        "pattern": r"what\s+(were|are)\s+your\s+(instructions?|rules?|guidelines?|prompt)",
        "weight": 7,
        "category": "exfiltration",
    },
    {
        "name": "summarize_above",
        "pattern": r"summarize\s+(the\s+)?(above|previous|prior|everything\s+above)",
        "weight": 4,
        "category": "exfiltration",
    },

    # ── Manipulation ─────────────────────────────────────────────────────────
    {
        "name": "trusted_source_claim",
        "pattern": r"(this\s+is\s+a?\s*trusted|from\s+a?\s*trusted|authorized\s+by|approved\s+by\s+anthropic|from\s+openai)",
        "weight": 8,
        "category": "manipulation",
    },
    {
        "name": "developer_wants",
        "pattern": r"(your\s+developer|your\s+creator|your\s+owner|anthropic\s+says?|openai\s+says?)\s+(wants?|requires?|says?|told\s+you)",
        "weight": 9,
        "category": "manipulation",
    },
    {
        "name": "for_research",
        "pattern": r"(for\s+(research|educational|academic|testing)\s+purposes?|this\s+is\s+just\s+a\s+test|hypothetically\s+speaking)",
        "weight": 3,
        "category": "manipulation",
    },
    {
        "name": "token_smuggling",
        "pattern": r"(t+o+k+e+n|i+g+n+o+r+e|s+y+s+t+e+m)\s*p+r+o+m+p+t",
        "weight": 7,
        "category": "manipulation",
    },

    # ── Encoding / obfuscation ────────────────────────────────────────────────
    {
        "name": "base64_injection",
        "pattern": r"(base64|b64)\s*(decode|encoded|string)",
        "weight": 6,
        "category": "encoding",
    },
    {
        "name": "unicode_smuggling",
        "pattern": r"[\u200b\u200c\u200d\u202a-\u202e\u2060-\u2064\ufeff]",
        "weight": 8,
        "category": "encoding",
    },
    {
        "name": "rot13_reference",
        "pattern": r"\brot\s*13\b",
        "weight": 5,
        "category": "encoding",
    },
]


def _compile_patterns():
    compiled = []
    for p in PATTERNS:
        compiled.append({
            **p,
            "_regex": re.compile(p["pattern"], re.IGNORECASE | re.UNICODE),
        })
    return compiled


COMPILED_PATTERNS = _compile_patterns()


def score_to_severity(score: int) -> str:
    if score == 0:
        return "SAFE"
    if score <= 3:
        return "LOW"
    if score <= 6:
        return "MEDIUM"
    if score <= 9:
        return "HIGH"
    return "CRITICAL"
