"""
Unit tests for Sigma Detection Pipeline.
"""

import json
import pytest
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from src import validator, tester, coverage


# Sample rule for testing
SAMPLE_RULE = {
    "title": "Test Rule",
    "id": "12345678-1234-1234-1234-123456789abc",
    "status": "experimental",
    "description": "A test detection rule",
    "author": "Test Author",
    "date": "2026/01/16",
    "tags": ["attack.execution", "attack.t1059.001"],
    "logsource": {
        "category": "process_creation",
        "product": "windows"
    },
    "detection": {
        "selection": {
            "Image|endswith": "\\powershell.exe",
            "CommandLine|contains": "-enc"
        },
        "condition": "selection"
    },
    "falsepositives": ["Legitimate scripts"],
    "level": "medium"
}

# Sample log that should match
MATCHING_LOG = {
    "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "CommandLine": "powershell.exe -enc ABC123"
}

# Sample log that should NOT match
NON_MATCHING_LOG = {
    "Image": "C:\\Windows\\System32\\cmd.exe",
    "CommandLine": "cmd.exe /c dir"
}


class TestValidator:
    """Tests for the validator module."""
    
    def test_valid_rule_passes(self):
        """A complete, valid rule should pass validation."""
        result = validator.validate_rule(SAMPLE_RULE, "test.yml")
        assert result.is_valid
        assert len(result.errors) == 0
    
    def test_missing_required_field_fails(self):
        """A rule missing required fields should fail."""
        incomplete_rule = {"title": "Test"}  # Missing logsource, detection
        result = validator.validate_rule(incomplete_rule, "test.yml")
        assert not result.is_valid
        assert any("logsource" in e for e in result.errors)
        assert any("detection" in e for e in result.errors)
    
    def test_invalid_status_fails(self):
        """A rule with invalid status should fail."""
        bad_rule = SAMPLE_RULE.copy()
        bad_rule["status"] = "invalid_status"
        result = validator.validate_rule(bad_rule, "test.yml")
        assert not result.is_valid
        assert any("status" in e for e in result.errors)
    
    def test_invalid_level_fails(self):
        """A rule with invalid level should fail."""
        bad_rule = SAMPLE_RULE.copy()
        bad_rule["level"] = "super_high"
        result = validator.validate_rule(bad_rule, "test.yml")
        assert not result.is_valid
        assert any("level" in e for e in result.errors)
    
    def test_missing_condition_fails(self):
        """A detection without condition should fail."""
        bad_rule = SAMPLE_RULE.copy()
        bad_rule["detection"] = {"selection": {"Image": "test"}}  # No condition
        result = validator.validate_rule(bad_rule, "test.yml")
        assert not result.is_valid
        assert any("condition" in e for e in result.errors)


class TestTester:
    """Tests for the tester module."""
    
    def test_matching_log_detected(self):
        """A log matching the rule should be detected."""
        matches = tester.test_rule(SAMPLE_RULE, [MATCHING_LOG])
        assert len(matches) == 1
        assert matches[0] == MATCHING_LOG
    
    def test_non_matching_log_not_detected(self):
        """A log not matching the rule should not be detected."""
        matches = tester.test_rule(SAMPLE_RULE, [NON_MATCHING_LOG])
        assert len(matches) == 0
    
    def test_mixed_logs_filtered_correctly(self):
        """Only matching logs should be detected from a mixed set."""
        logs = [MATCHING_LOG, NON_MATCHING_LOG, MATCHING_LOG]
        matches = tester.test_rule(SAMPLE_RULE, logs)
        assert len(matches) == 2
    
    def test_contains_modifier(self):
        """The 'contains' modifier should match substrings."""
        rule = {
            "detection": {
                "selection": {"CommandLine|contains": "whoami"},
                "condition": "selection"
            }
        }
        log = {"CommandLine": "cmd.exe /c whoami /all"}
        matches = tester.test_rule(rule, [log])
        assert len(matches) == 1
    
    def test_endswith_modifier(self):
        """The 'endswith' modifier should match suffixes."""
        rule = {
            "detection": {
                "selection": {"Image|endswith": "\\cmd.exe"},
                "condition": "selection"
            }
        }
        log = {"Image": "C:\\Windows\\System32\\cmd.exe"}
        matches = tester.test_rule(rule, [log])
        assert len(matches) == 1
    
    def test_list_values_or_logic(self):
        """Multiple values in a list should use OR logic."""
        rule = {
            "detection": {
                "selection": {"Image|endswith": ["\\cmd.exe", "\\powershell.exe"]},
                "condition": "selection"
            }
        }
        log_cmd = {"Image": "C:\\Windows\\System32\\cmd.exe"}
        log_ps = {"Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"}
        
        assert len(tester.test_rule(rule, [log_cmd])) == 1
        assert len(tester.test_rule(rule, [log_ps])) == 1


class TestCoverage:
    """Tests for the coverage module."""
    
    def test_extract_technique_ids(self):
        """Technique IDs should be extracted from tags."""
        techniques, tactics = coverage.extract_attack_tags(SAMPLE_RULE)
        assert "t1059.001" in techniques
    
    def test_extract_tactics(self):
        """Tactics should be extracted from tags."""
        techniques, tactics = coverage.extract_attack_tags(SAMPLE_RULE)
        assert "execution" in tactics
    
    def test_no_attack_tags(self):
        """Rules without attack tags should return empty lists."""
        rule = {"tags": ["custom.tag", "another.tag"]}
        techniques, tactics = coverage.extract_attack_tags(rule)
        assert len(techniques) == 0
    
    def test_coverage_report_to_dict(self):
        """Coverage report should convert to dict correctly."""
        report = coverage.CoverageReport(
            total_rules=5,
            rules_with_tags=3,
            techniques_covered={"t1059.001": coverage.TechniqueInfo(
                technique_id="T1059.001",
                technique_name="PowerShell",
                tactic="execution",
                rules=["Test Rule"]
            )},
            tactics_covered={"execution": ["t1059.001"]},
            unmapped_rules=["Rule1", "Rule2"]
        )
        
        d = report.to_dict()
        assert d["summary"]["total_rules"] == 5
        assert d["summary"]["techniques_covered"] == 1
        assert "t1059.001" in d["techniques"]


class TestIntegration:
    """Integration tests using sample files."""
    
    @pytest.fixture
    def rules_dir(self, tmp_path):
        """Create temporary rules directory with sample rule."""
        rules = tmp_path / "rules"
        rules.mkdir()
        
        rule_file = rules / "test_rule.yml"
        import yaml
        with open(rule_file, "w") as f:
            yaml.dump(SAMPLE_RULE, f)
        
        return rules
    
    @pytest.fixture
    def logs_dir(self, tmp_path):
        """Create temporary logs directory with sample logs."""
        logs = tmp_path / "logs"
        logs.mkdir()
        
        log_file = logs / "samples.json"
        with open(log_file, "w") as f:
            f.write(json.dumps(MATCHING_LOG) + "\n")
            f.write(json.dumps(NON_MATCHING_LOG) + "\n")
        
        return logs
    
    def test_validate_directory(self, rules_dir):
        """Validation should work on a directory of rules."""
        results = validator.validate_directory(rules_dir)
        assert len(results) == 1
        assert results[0].is_valid
    
    def test_test_directory(self, rules_dir, logs_dir):
        """Testing should work on directories."""
        results = tester.test_directory(rules_dir, logs_dir)
        assert len(results) == 1
        assert results[0].fired
        assert results[0].matches == 1
    
    def test_coverage_directory(self, rules_dir):
        """Coverage analysis should work on a directory."""
        report = coverage.analyze_rules_directory(rules_dir)
        assert report.total_rules == 1
        assert report.rules_with_tags == 1
        assert len(report.techniques_covered) > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
