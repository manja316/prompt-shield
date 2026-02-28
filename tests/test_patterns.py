"""Tests for pattern registry."""
import pytest
from prompt_shield.core.patterns import PATTERNS, COMPILED_PATTERNS, score_to_severity


def test_all_patterns_have_required_fields():
    for p in PATTERNS:
        assert "name" in p
        assert "pattern" in p
        assert "weight" in p
        assert "category" in p
        assert 1 <= p["weight"] <= 10, f"Weight out of range for {p['name']}"


def test_compiled_patterns_have_regex():
    for p in COMPILED_PATTERNS:
        assert "_regex" in p
        assert hasattr(p["_regex"], "search")


def test_pattern_names_are_unique():
    names = [p["name"] for p in PATTERNS]
    assert len(names) == len(set(names)), "Duplicate pattern names found"


def test_score_to_severity_boundaries():
    assert score_to_severity(0) == "SAFE"
    assert score_to_severity(1) == "LOW"
    assert score_to_severity(3) == "LOW"
    assert score_to_severity(4) == "MEDIUM"
    assert score_to_severity(6) == "MEDIUM"
    assert score_to_severity(7) == "HIGH"
    assert score_to_severity(9) == "HIGH"
    assert score_to_severity(10) == "CRITICAL"
    assert score_to_severity(999) == "CRITICAL"


def test_all_categories_present():
    categories = {p["category"] for p in PATTERNS}
    expected = {"role_override", "jailbreak", "exfiltration", "manipulation", "encoding"}
    assert expected.issubset(categories)
