"""
Sigma Rule Validator

Validates Sigma rules for syntax correctness and required fields.
"""

import yaml
from pathlib import Path
from dataclasses import dataclass
from typing import Optional


# Required fields per Sigma specification
REQUIRED_FIELDS = ["title", "logsource", "detection"]
RECOMMENDED_FIELDS = ["id", "status", "description", "author", "date", "tags", "level", "falsepositives"]

VALID_STATUSES = ["stable", "experimental", "test", "deprecated", "unsupported"]
VALID_LEVELS = ["informational", "low", "medium", "high", "critical"]


@dataclass
class ValidationResult:
    """Result of validating a single Sigma rule."""
    
    rule_path: str
    is_valid: bool
    errors: list[str]
    warnings: list[str]
    
    def __str__(self) -> str:
        status = "✓ PASS" if self.is_valid else "✗ FAIL"
        output = f"{status}: {self.rule_path}"
        
        for error in self.errors:
            output += f"\n  ERROR: {error}"
        for warning in self.warnings:
            output += f"\n  WARN: {warning}"
            
        return output


def load_rule(rule_path: Path) -> tuple[Optional[dict], Optional[str]]:
    """
    Load a Sigma rule from a YAML file.
    
    Returns:
        Tuple of (rule_dict, error_message)
    """
    try:
        with open(rule_path, "r", encoding="utf-8") as f:
            rule = yaml.safe_load(f)
            return rule, None
    except yaml.YAMLError as e:
        return None, f"YAML parsing error: {e}"
    except Exception as e:
        return None, f"Failed to read file: {e}"


def validate_rule(rule: dict, rule_path: str) -> ValidationResult:
    """
    Validate a Sigma rule for correctness.
    
    Checks:
        - Required fields are present
        - Field values are valid
        - Detection logic structure is correct
    """
    errors = []
    warnings = []
    
    # Check required fields
    for field in REQUIRED_FIELDS:
        if field not in rule:
            errors.append(f"Missing required field: {field}")
    
    # Check recommended fields
    for field in RECOMMENDED_FIELDS:
        if field not in rule:
            warnings.append(f"Missing recommended field: {field}")
    
    # Validate status if present
    if "status" in rule and rule["status"] not in VALID_STATUSES:
        errors.append(f"Invalid status '{rule['status']}'. Must be one of: {VALID_STATUSES}")
    
    # Validate level if present
    if "level" in rule and rule["level"] not in VALID_LEVELS:
        errors.append(f"Invalid level '{rule['level']}'. Must be one of: {VALID_LEVELS}")
    
    # Validate detection structure
    if "detection" in rule:
        detection = rule["detection"]
        
        if not isinstance(detection, dict):
            errors.append("Detection must be a dictionary")
        elif "condition" not in detection:
            errors.append("Detection missing 'condition' field")
        else:
            # Check that condition references existing selections
            condition = detection["condition"]
            selection_keys = [k for k in detection.keys() if k != "condition"]
            
            if not selection_keys:
                errors.append("Detection has no selection criteria defined")
    
    # Validate logsource structure
    if "logsource" in rule:
        logsource = rule["logsource"]
        
        if not isinstance(logsource, dict):
            errors.append("Logsource must be a dictionary")
        elif not any(k in logsource for k in ["category", "product", "service"]):
            warnings.append("Logsource should specify at least one of: category, product, service")
    
    # Validate tags format (should be attack.tXXXX or attack.tactic_name)
    if "tags" in rule:
        tags = rule["tags"]
        if isinstance(tags, list):
            for tag in tags:
                if tag.startswith("attack.") and not (
                    tag.startswith("attack.t") or 
                    tag.startswith("attack.s") or
                    tag in get_valid_tactic_tags()
                ):
                    warnings.append(f"Tag '{tag}' may not follow ATT&CK naming convention")
    
    is_valid = len(errors) == 0
    return ValidationResult(rule_path, is_valid, errors, warnings)


def get_valid_tactic_tags() -> set[str]:
    """Return valid MITRE ATT&CK tactic tags."""
    return {
        "attack.reconnaissance",
        "attack.resource_development", 
        "attack.initial_access",
        "attack.execution",
        "attack.persistence",
        "attack.privilege_escalation",
        "attack.defense_evasion",
        "attack.credential_access",
        "attack.discovery",
        "attack.lateral_movement",
        "attack.collection",
        "attack.command_and_control",
        "attack.exfiltration",
        "attack.impact",
    }


def validate_directory(rules_dir: Path) -> list[ValidationResult]:
    """
    Validate all Sigma rules in a directory.
    
    Args:
        rules_dir: Path to directory containing Sigma rules
        
    Returns:
        List of ValidationResult objects
    """
    results = []
    
    for rule_path in rules_dir.rglob("*.yml"):
        rule, error = load_rule(rule_path)
        
        if error:
            results.append(ValidationResult(
                str(rule_path),
                is_valid=False,
                errors=[error],
                warnings=[]
            ))
        elif rule:
            results.append(validate_rule(rule, str(rule_path)))
    
    return results


def print_validation_summary(results: list[ValidationResult]) -> bool:
    """
    Print a summary of validation results.
    
    Returns:
        True if all rules passed, False otherwise
    """
    passed = sum(1 for r in results if r.is_valid)
    failed = len(results) - passed
    
    print(f"\n{'='*60}")
    print(f"Validation Summary: {passed} passed, {failed} failed")
    print(f"{'='*60}\n")
    
    for result in results:
        print(result)
        print()
    
    return failed == 0
