"""Exceptions for prompt-shield."""


class InjectionRiskError(Exception):
    """Raised when a prompt exceeds the configured risk threshold.

    Attributes:
        severity:   String label — LOW, MEDIUM, HIGH, or CRITICAL.
        risk_score: Numeric score that triggered the block.
        matches:    List of pattern names that matched.
        text:       The scanned input (may be truncated for safety).
    """

    def __init__(self, severity: str, risk_score: int, matches: list, text: str = ""):
        self.severity = severity
        self.risk_score = risk_score
        self.matches = matches
        self.text = text[:200]  # never log full prompt in exception
        super().__init__(
            f"Injection risk detected: severity={severity}, score={risk_score}, "
            f"patterns={matches}"
        )
