"""
Detection Tester

Tests Sigma rules against log samples to verify detection logic fires correctly.
"""

import json
import yaml
import re
from pathlib import Path
from dataclasses import dataclass
from typing import Any, Optional


@dataclass
class TestResult:
    """Result of testing a detection rule against log samples."""
    
    rule_path: str
    rule_title: str
    total_logs: int
    matches: int
    matched_logs: list[dict]
    
    @property
    def fired(self) -> bool:
        return self.matches > 0
    
    def __str__(self) -> str:
        status = "✓ FIRED" if self.fired else "✗ NO MATCH"
        return f"{status}: {self.rule_title} ({self.matches}/{self.total_logs} logs matched)"


def load_sigma_rule(rule_path: Path) -> dict:
    """Load a Sigma rule from YAML file."""
    with open(rule_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def load_log_samples(log_path: Path) -> list[dict]:
    """
    Load log samples from a JSON file.
    
    Supports both JSON Lines format and JSON array format.
    """
    with open(log_path, "r", encoding="utf-8") as f:
        content = f.read().strip()
        
        # Try JSON Lines format first
        if content.startswith("{"):
            return [json.loads(line) for line in content.split("\n") if line.strip()]
        # Then try JSON array
        else:
            return json.loads(content)


def normalize_field_name(field: str) -> str:
    """Extract base field name without modifiers."""
    return field.split("|")[0]


def get_field_modifiers(field: str) -> list[str]:
    """Extract modifiers from field specification."""
    parts = field.split("|")
    return parts[1:] if len(parts) > 1 else []


def get_nested_value(log: dict, field: str) -> Any:
    """
    Get a value from a log entry, supporting nested fields.
    
    Handles both dot notation (Event.System.EventID) and flat fields.
    """
    # Try direct access first
    if field in log:
        return log[field]
    
    # Try nested access
    parts = field.split(".")
    value = log
    
    for part in parts:
        if isinstance(value, dict) and part in value:
            value = value[part]
        else:
            return None
    
    return value


def match_value(log_value: Any, condition: Any, modifiers: list[str]) -> bool:
    """
    Check if a log value matches a condition with given modifiers.
    
    Supported modifiers:
        - contains: substring match
        - endswith: suffix match
        - startswith: prefix match
        - re: regex match
        - all: all values must match (for lists)
    """
    if log_value is None:
        return False
    
    # Convert to string for comparison
    log_str = str(log_value).lower()
    
    # Handle list conditions (OR logic by default)
    if isinstance(condition, list):
        if "all" in modifiers:
            return all(match_single_value(log_str, str(c).lower(), modifiers) for c in condition)
        else:
            return any(match_single_value(log_str, str(c).lower(), modifiers) for c in condition)
    
    return match_single_value(log_str, str(condition).lower(), modifiers)


def match_single_value(log_value: str, condition: str, modifiers: list[str]) -> bool:
    """Match a single value against a condition."""
    
    if "re" in modifiers:
        try:
            return bool(re.search(condition, log_value, re.IGNORECASE))
        except re.error:
            return False
    
    if "contains" in modifiers:
        return condition in log_value
    
    if "endswith" in modifiers:
        return log_value.endswith(condition)
    
    if "startswith" in modifiers:
        return log_value.startswith(condition)
    
    # Default: exact match (case-insensitive)
    return log_value == condition


def evaluate_selection(log: dict, selection: dict) -> bool:
    """
    Evaluate if a log entry matches a selection criteria.
    
    All fields in the selection must match (AND logic).
    """
    for field_spec, condition in selection.items():
        field_name = normalize_field_name(field_spec)
        modifiers = get_field_modifiers(field_spec)
        
        log_value = get_nested_value(log, field_name)
        
        if not match_value(log_value, condition, modifiers):
            return False
    
    return True


def evaluate_condition(log: dict, detection: dict) -> bool:
    """
    Evaluate the detection condition against a log entry.
    
    Supports basic conditions:
        - selection
        - selection1 and selection2
        - selection1 or selection2
        - selection and not filter
    """
    condition = detection.get("condition", "")
    
    # Build a context of selection results
    context = {}
    for key, value in detection.items():
        if key != "condition" and isinstance(value, dict):
            context[key] = evaluate_selection(log, value)
    
    # Parse and evaluate the condition
    # Simple implementation - handles common patterns
    try:
        # Replace selection names with their boolean results
        eval_condition = condition
        
        # Sort by length (longest first) to avoid partial replacements
        for name in sorted(context.keys(), key=len, reverse=True):
            eval_condition = eval_condition.replace(name, str(context[name]))
        
        # Replace logical operators
        eval_condition = eval_condition.replace(" and ", " and ")
        eval_condition = eval_condition.replace(" or ", " or ")
        eval_condition = eval_condition.replace(" not ", " not ")
        
        # Evaluate the boolean expression
        return eval(eval_condition, {"__builtins__": {}}, {})
    
    except Exception:
        # Fallback: if condition is just "selection", check if it exists and matched
        if condition in context:
            return context[condition]
        return False


def test_rule(rule: dict, logs: list[dict]) -> list[dict]:
    """
    Test a Sigma rule against a list of log entries.
    
    Returns:
        List of log entries that matched the detection.
    """
    detection = rule.get("detection", {})
    
    if not detection:
        return []
    
    return [log for log in logs if evaluate_condition(log, detection)]


def test_rule_file(rule_path: Path, logs: list[dict]) -> TestResult:
    """Test a Sigma rule file against log samples."""
    rule = load_sigma_rule(rule_path)
    matches = test_rule(rule, logs)
    
    return TestResult(
        rule_path=str(rule_path),
        rule_title=rule.get("title", "Unknown"),
        total_logs=len(logs),
        matches=len(matches),
        matched_logs=matches
    )


def find_matching_logs(rule_path: Path, log_dir: Path) -> Optional[Path]:
    """
    Find log samples that might match a rule based on naming conventions.
    
    Looks for:
        1. Exact match: rule_name.yml -> rule_name.json
        2. Category match: execution/rule.yml -> execution_logs.json
    """
    rule_stem = rule_path.stem
    
    # Try exact match
    exact_match = log_dir / f"{rule_stem}.json"
    if exact_match.exists():
        return exact_match
    
    # Try category match
    category = rule_path.parent.name
    category_match = log_dir / f"{category}.json"
    if category_match.exists():
        return category_match
    
    # Try generic samples
    generic = log_dir / "samples.json"
    if generic.exists():
        return generic
    
    return None


def test_directory(rules_dir: Path, logs_dir: Path) -> list[TestResult]:
    """
    Test all Sigma rules in a directory against corresponding log samples.
    
    Args:
        rules_dir: Directory containing Sigma rules
        logs_dir: Directory containing log samples
        
    Returns:
        List of TestResult objects
    """
    results = []
    
    # Load all available log samples
    all_logs = []
    for log_file in logs_dir.glob("*.json"):
        try:
            all_logs.extend(load_log_samples(log_file))
        except Exception as e:
            print(f"Warning: Failed to load {log_file}: {e}")
    
    # Test each rule
    for rule_path in rules_dir.rglob("*.yml"):
        try:
            # Try to find specific logs for this rule
            specific_logs = find_matching_logs(rule_path, logs_dir)
            
            if specific_logs:
                logs = load_log_samples(specific_logs)
            else:
                logs = all_logs
            
            if logs:
                result = test_rule_file(rule_path, logs)
                results.append(result)
            else:
                print(f"Warning: No log samples found for {rule_path}")
                
        except Exception as e:
            print(f"Error testing {rule_path}: {e}")
    
    return results


def print_test_summary(results: list[TestResult]) -> bool:
    """
    Print a summary of test results.
    
    Returns:
        True if at least one detection fired, False otherwise
    """
    fired = sum(1 for r in results if r.fired)
    
    print(f"\n{'='*60}")
    print(f"Test Summary: {fired}/{len(results)} detections fired")
    print(f"{'='*60}\n")
    
    for result in results:
        print(result)
    
    return fired > 0
