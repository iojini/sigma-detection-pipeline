"""
MITRE ATT&CK Coverage Reporter

Analyzes Sigma rules and generates coverage reports mapped to MITRE ATT&CK.
"""

import json
import yaml
import re
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional
from collections import defaultdict


# MITRE ATT&CK Tactic IDs and Names
TACTICS = {
    "reconnaissance": "TA0043",
    "resource_development": "TA0042",
    "initial_access": "TA0001",
    "execution": "TA0002",
    "persistence": "TA0003",
    "privilege_escalation": "TA0004",
    "defense_evasion": "TA0005",
    "credential_access": "TA0006",
    "discovery": "TA0007",
    "lateral_movement": "TA0008",
    "collection": "TA0009",
    "command_and_control": "TA0011",
    "exfiltration": "TA0010",
    "impact": "TA0040",
}


@dataclass
class TechniqueInfo:
    """Information about a detected technique."""
    technique_id: str
    technique_name: str
    tactic: str
    rules: list[str] = field(default_factory=list)


@dataclass 
class CoverageReport:
    """Complete coverage report for a set of Sigma rules."""
    total_rules: int
    rules_with_tags: int
    techniques_covered: dict[str, TechniqueInfo]
    tactics_covered: dict[str, list[str]]
    unmapped_rules: list[str]
    
    def to_dict(self) -> dict:
        """Convert report to dictionary for JSON serialization."""
        return {
            "summary": {
                "total_rules": self.total_rules,
                "rules_with_attack_tags": self.rules_with_tags,
                "techniques_covered": len(self.techniques_covered),
                "tactics_covered": len(self.tactics_covered),
            },
            "techniques": {
                tid: {
                    "id": info.technique_id,
                    "name": info.technique_name,
                    "tactic": info.tactic,
                    "rules": info.rules,
                    "rule_count": len(info.rules),
                }
                for tid, info in self.techniques_covered.items()
            },
            "tactics": {
                tactic: {
                    "id": TACTICS.get(tactic, "Unknown"),
                    "techniques": techniques,
                    "technique_count": len(techniques),
                }
                for tactic, techniques in self.tactics_covered.items()
            },
            "unmapped_rules": self.unmapped_rules,
        }
    
    def to_json(self, indent: int = 2) -> str:
        """Convert report to JSON string."""
        return json.dumps(self.to_dict(), indent=indent)
    
    def to_navigator_layer(self) -> dict:
        """
        Generate MITRE ATT&CK Navigator layer format.
        
        This can be imported into https://mitre-attack.github.io/attack-navigator/
        """
        techniques = []
        
        for tid, info in self.techniques_covered.items():
            # Extract base technique ID (without sub-technique)
            base_id = tid.split(".")[0]
            
            techniques.append({
                "techniqueID": tid.upper(),
                "tactic": info.tactic.replace("_", "-"),
                "score": len(info.rules),  # Score by number of rules
                "color": "",  # Let Navigator choose based on score
                "comment": f"Covered by {len(info.rules)} rule(s): {', '.join(info.rules[:3])}{'...' if len(info.rules) > 3 else ''}",
                "enabled": True,
            })
        
        return {
            "name": "Sigma Detection Coverage",
            "versions": {
                "attack": "14",
                "navigator": "4.9.1",
                "layer": "4.5",
            },
            "domain": "enterprise-attack",
            "description": "MITRE ATT&CK coverage from Sigma detection rules",
            "filters": {
                "platforms": ["Windows", "Linux", "macOS"],
            },
            "sorting": 0,
            "layout": {
                "layout": "side",
                "aggregateFunction": "average",
                "showID": True,
                "showName": True,
            },
            "hideDisabled": False,
            "techniques": techniques,
            "gradient": {
                "colors": ["#ffffff", "#66b3ff", "#0066cc"],
                "minValue": 0,
                "maxValue": 5,
            },
            "metadata": [],
            "showTacticRowBackground": True,
            "tacticRowBackground": "#dddddd",
            "selectTechniquesAcrossTactics": True,
        }


def extract_attack_tags(rule: dict) -> tuple[list[str], list[str]]:
    """
    Extract MITRE ATT&CK technique IDs and tactics from rule tags.
    
    Returns:
        Tuple of (technique_ids, tactics)
    """
    tags = rule.get("tags", [])
    
    if not isinstance(tags, list):
        return [], []
    
    techniques = []
    tactics = []
    
    for tag in tags:
        if not isinstance(tag, str):
            continue
            
        tag_lower = tag.lower()
        
        # Match technique IDs: attack.t1059, attack.t1059.001
        technique_match = re.match(r"attack\.(t\d{4}(?:\.\d{3})?)", tag_lower)
        if technique_match:
            techniques.append(technique_match.group(1))
            continue
        
        # Match sub-technique IDs: attack.s0001
        subtechnique_match = re.match(r"attack\.(s\d{4})", tag_lower)
        if subtechnique_match:
            techniques.append(subtechnique_match.group(1))
            continue
        
        # Match tactics: attack.execution, attack.persistence
        tactic_match = re.match(r"attack\.([a-z_]+)", tag_lower)
        if tactic_match:
            tactic = tactic_match.group(1)
            if tactic in TACTICS:
                tactics.append(tactic)
    
    return techniques, tactics


def get_technique_name(technique_id: str) -> str:
    """
    Get human-readable name for a technique ID.
    
    This is a simplified mapping - a production version would
    use the full ATT&CK STIX data.
    """
    # Common techniques mapping
    TECHNIQUE_NAMES = {
        "t1059": "Command and Scripting Interpreter",
        "t1059.001": "PowerShell",
        "t1059.003": "Windows Command Shell",
        "t1003": "OS Credential Dumping",
        "t1003.001": "LSASS Memory",
        "t1547": "Boot or Logon Autostart Execution",
        "t1547.001": "Registry Run Keys / Startup Folder",
        "t1218": "System Binary Proxy Execution",
        "t1218.011": "Rundll32",
        "t1087": "Account Discovery",
        "t1087.001": "Local Account",
        "t1087.002": "Domain Account",
        "t1027": "Obfuscated Files or Information",
        "t1055": "Process Injection",
        "t1070": "Indicator Removal",
        "t1070.001": "Clear Windows Event Logs",
        "t1105": "Ingress Tool Transfer",
        "t1021": "Remote Services",
        "t1021.001": "Remote Desktop Protocol",
        "t1071": "Application Layer Protocol",
        "t1071.001": "Web Protocols",
        "t1078": "Valid Accounts",
        "t1110": "Brute Force",
        "t1562": "Impair Defenses",
        "t1562.001": "Disable or Modify Tools",
    }
    
    return TECHNIQUE_NAMES.get(technique_id.lower(), f"Technique {technique_id.upper()}")


def get_tactic_for_technique(technique_id: str) -> str:
    """
    Get the primary tactic for a technique.
    
    This is simplified - techniques can belong to multiple tactics.
    """
    TECHNIQUE_TACTICS = {
        "t1059": "execution",
        "t1003": "credential_access",
        "t1547": "persistence",
        "t1218": "defense_evasion",
        "t1087": "discovery",
        "t1027": "defense_evasion",
        "t1055": "defense_evasion",
        "t1070": "defense_evasion",
        "t1105": "command_and_control",
        "t1021": "lateral_movement",
        "t1071": "command_and_control",
        "t1078": "initial_access",
        "t1110": "credential_access",
        "t1562": "defense_evasion",
    }
    
    # Get base technique
    base = technique_id.lower().split(".")[0]
    return TECHNIQUE_TACTICS.get(base, "unknown")


def analyze_rules_directory(rules_dir: Path) -> CoverageReport:
    """
    Analyze all Sigma rules in a directory and generate a coverage report.
    
    Args:
        rules_dir: Path to directory containing Sigma rules
        
    Returns:
        CoverageReport with ATT&CK coverage analysis
    """
    techniques_covered: dict[str, TechniqueInfo] = {}
    tactics_covered: defaultdict[str, list[str]] = defaultdict(list)
    unmapped_rules: list[str] = []
    
    total_rules = 0
    rules_with_tags = 0
    
    for rule_path in rules_dir.rglob("*.yml"):
        try:
            with open(rule_path, "r", encoding="utf-8") as f:
                rule = yaml.safe_load(f)
        except Exception as e:
            print(f"Warning: Failed to parse {rule_path}: {e}")
            continue
        
        total_rules += 1
        rule_title = rule.get("title", rule_path.stem)
        
        techniques, tactics = extract_attack_tags(rule)
        
        if not techniques:
            unmapped_rules.append(rule_title)
            continue
        
        rules_with_tags += 1
        
        for technique_id in techniques:
            # Determine tactic from tags or lookup
            tactic = tactics[0] if tactics else get_tactic_for_technique(technique_id)
            
            if technique_id not in techniques_covered:
                techniques_covered[technique_id] = TechniqueInfo(
                    technique_id=technique_id.upper(),
                    technique_name=get_technique_name(technique_id),
                    tactic=tactic,
                    rules=[]
                )
            
            techniques_covered[technique_id].rules.append(rule_title)
            
            if technique_id not in tactics_covered[tactic]:
                tactics_covered[tactic].append(technique_id)
    
    return CoverageReport(
        total_rules=total_rules,
        rules_with_tags=rules_with_tags,
        techniques_covered=techniques_covered,
        tactics_covered=dict(tactics_covered),
        unmapped_rules=unmapped_rules,
    )


def print_coverage_summary(report: CoverageReport) -> None:
    """Print a human-readable coverage summary."""
    print(f"\n{'='*60}")
    print("MITRE ATT&CK Coverage Report")
    print(f"{'='*60}\n")
    
    print(f"Total Rules Analyzed: {report.total_rules}")
    print(f"Rules with ATT&CK Tags: {report.rules_with_tags}")
    print(f"Techniques Covered: {len(report.techniques_covered)}")
    print(f"Tactics Covered: {len(report.tactics_covered)}")
    
    print(f"\n{'-'*40}")
    print("Coverage by Tactic:")
    print(f"{'-'*40}")
    
    for tactic, techniques in sorted(report.tactics_covered.items()):
        tactic_id = TACTICS.get(tactic, "N/A")
        print(f"\n  {tactic.replace('_', ' ').title()} ({tactic_id}):")
        for tid in techniques:
            info = report.techniques_covered.get(tid)
            if info:
                print(f"    - {tid.upper()}: {info.technique_name} ({len(info.rules)} rules)")
    
    if report.unmapped_rules:
        print(f"\n{'-'*40}")
        print(f"Rules without ATT&CK mapping ({len(report.unmapped_rules)}):")
        print(f"{'-'*40}")
        for rule in report.unmapped_rules[:10]:
            print(f"  - {rule}")
        if len(report.unmapped_rules) > 10:
            print(f"  ... and {len(report.unmapped_rules) - 10} more")


def save_report(report: CoverageReport, output_path: Path, include_navigator: bool = True) -> None:
    """
    Save coverage report to files.
    
    Args:
        report: CoverageReport to save
        output_path: Base path for output files
        include_navigator: Also generate ATT&CK Navigator layer
    """
    # Save JSON report
    json_path = output_path.with_suffix(".json")
    with open(json_path, "w", encoding="utf-8") as f:
        f.write(report.to_json())
    print(f"Coverage report saved to: {json_path}")
    
    # Save Navigator layer
    if include_navigator:
        nav_path = output_path.with_name(f"{output_path.stem}_navigator.json")
        with open(nav_path, "w", encoding="utf-8") as f:
            json.dump(report.to_navigator_layer(), f, indent=2)
        print(f"ATT&CK Navigator layer saved to: {nav_path}")
