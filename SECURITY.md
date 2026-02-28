# Security Policy

## What this library protects against

`prompt-shield` detects prompt injection attacks before they reach your LLM:

- **Role override attacks** — attempts to redefine the AI's identity or instructions
- **Jailbreak attempts** — DAN, developer mode, unrestricted mode patterns
- **Data exfiltration** — attempts to extract system prompts or training context
- **Manipulation** — fake authority claims, unicode smuggling, encoding tricks

## What this library does NOT replace

- Input sanitization for SQL/XSS/other injection types
- Output filtering (use a separate output guard for that)
- Rate limiting and cost control (use [`ai-cost-guard`](https://github.com/manja316/ai-cost-guard))

## Limitations

Pattern-based detection has false positives and false negatives.
This library is a defense-in-depth layer, not a complete solution.
Sophisticated adversarial inputs may bypass pattern matching.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | ✅        |

## Reporting a Vulnerability

Report via GitHub Issues (mark as "security").
Do NOT include sensitive prompts or API keys in public issues.

Expected response: 48 hours.
