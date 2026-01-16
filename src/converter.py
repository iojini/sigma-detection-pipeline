"""
Sigma Rule Converter

Converts Sigma rules to various SIEM query languages using pySigma.
"""

import yaml
from pathlib import Path
from dataclasses import dataclass
from typing import Optional


@dataclass
class ConversionResult:
    """Result of converting a Sigma rule."""
    
    rule_path: str
    rule_title: str
    target_format: str
    success: bool
    query: Optional[str]
    error: Optional[str]
    
    def __str__(self) -> str:
        if self.success:
            return f"✓ {self.rule_title}\n{self.query}"
        else:
            return f"✗ {self.rule_title}: {self.error}"


def convert_rule_native(rule: dict, target_format: str) -> tuple[Optional[str], Optional[str]]:
    """
    Convert a Sigma rule to target format using native implementation.
    
    This is a simplified converter for demonstration.
    For production use, prefer pySigma backends.
    
    Args:
        rule: Parsed Sigma rule dict
        target_format: Target query language (kusto, splunk)
        
    Returns:
        Tuple of (query, error)
    """
    detection = rule.get("detection", {})
    condition = detection.get("condition", "selection")
    
    # Get the selection(s) referenced in condition
    selections = {k: v for k, v in detection.items() if k != "condition"}
    
    if not selections:
        return None, "No selection criteria found"
    
    if target_format == "kusto":
        return _to_kusto(rule, selections, condition)
    elif target_format == "splunk":
        return _to_splunk(rule, selections, condition)
    else:
        return None, f"Unsupported format: {target_format}"


def _to_kusto(rule: dict, selections: dict, condition: str) -> tuple[Optional[str], Optional[str]]:
    """Convert to Kusto Query Language (KQL) for Microsoft Sentinel."""
    
    logsource = rule.get("logsource", {})
    category = logsource.get("category", "")
    product = logsource.get("product", "")
    
    # Determine table based on logsource
    if category == "process_creation":
        table = "DeviceProcessEvents"
    elif category == "registry_event":
        table = "DeviceRegistryEvents"
    elif category == "network_connection":
        table = "DeviceNetworkEvents"
    elif category == "file_event":
        table = "DeviceFileEvents"
    elif product == "windows" and logsource.get("service") == "security":
        table = "SecurityEvent"
    else:
        table = "DeviceEvents"  # Default fallback
    
    # Build WHERE clauses
    where_clauses = []
    
    for name, selection in selections.items():
        clause_parts = []
        
        for field_spec, value in selection.items():
            field = field_spec.split("|")[0]
            modifiers = field_spec.split("|")[1:] if "|" in field_spec else []
            
            # Map Sigma field names to Kusto
            kusto_field = _map_field_to_kusto(field)
            
            if isinstance(value, list):
                # Multiple values - OR condition
                if "contains" in modifiers:
                    conditions = [f'{kusto_field} contains "{v}"' for v in value]
                elif "endswith" in modifiers:
                    conditions = [f'{kusto_field} endswith "{v}"' for v in value]
                elif "startswith" in modifiers:
                    conditions = [f'{kusto_field} startswith "{v}"' for v in value]
                else:
                    conditions = [f'{kusto_field} == "{v}"' for v in value]
                clause_parts.append(f"({' or '.join(conditions)})")
            else:
                # Single value
                if "contains" in modifiers:
                    clause_parts.append(f'{kusto_field} contains "{value}"')
                elif "endswith" in modifiers:
                    clause_parts.append(f'{kusto_field} endswith "{value}"')
                elif "startswith" in modifiers:
                    clause_parts.append(f'{kusto_field} startswith "{value}"')
                else:
                    clause_parts.append(f'{kusto_field} == "{value}"')
        
        if clause_parts:
            where_clauses.append(f"({' and '.join(clause_parts)})")
    
    # Handle condition logic
    if "and" in condition:
        where_combined = " and ".join(where_clauses)
    elif "or" in condition:
        where_combined = " or ".join(where_clauses)
    else:
        where_combined = where_clauses[0] if where_clauses else "true"
    
    # Handle 'not' in condition
    if " not " in condition:
        # Simple handling - would need more sophisticated parsing for complex conditions
        pass
    
    query = f"""{table}
| where {where_combined}
| project TimeGenerated, {_get_project_fields(category)}"""
    
    return query, None


def _to_splunk(rule: dict, selections: dict, condition: str) -> tuple[Optional[str], Optional[str]]:
    """Convert to Splunk Search Processing Language (SPL)."""
    
    logsource = rule.get("logsource", {})
    category = logsource.get("category", "")
    product = logsource.get("product", "")
    
    # Determine index/sourcetype based on logsource
    if category == "process_creation":
        source = 'index=windows sourcetype="WinEventLog:Security" EventCode=4688'
    elif category == "registry_event":
        source = 'index=windows sourcetype="WinEventLog:Security" EventCode IN (4656, 4657, 4658, 4660, 4663)'
    elif product == "windows":
        source = 'index=windows sourcetype="WinEventLog:*"'
    else:
        source = 'index=main'
    
    # Build search clauses
    search_parts = []
    
    for name, selection in selections.items():
        clause_parts = []
        
        for field_spec, value in selection.items():
            field = field_spec.split("|")[0]
            modifiers = field_spec.split("|")[1:] if "|" in field_spec else []
            
            # Map Sigma field names to Splunk
            splunk_field = _map_field_to_splunk(field)
            
            if isinstance(value, list):
                if "contains" in modifiers:
                    conditions = [f'{splunk_field}="*{v}*"' for v in value]
                elif "endswith" in modifiers:
                    conditions = [f'{splunk_field}="*{v}"' for v in value]
                elif "startswith" in modifiers:
                    conditions = [f'{splunk_field}="{v}*"' for v in value]
                else:
                    conditions = [f'{splunk_field}="{v}"' for v in value]
                clause_parts.append(f"({' OR '.join(conditions)})")
            else:
                if "contains" in modifiers:
                    clause_parts.append(f'{splunk_field}="*{value}*"')
                elif "endswith" in modifiers:
                    clause_parts.append(f'{splunk_field}="*{value}"')
                elif "startswith" in modifiers:
                    clause_parts.append(f'{splunk_field}="{value}*"')
                else:
                    clause_parts.append(f'{splunk_field}="{value}"')
        
        if clause_parts:
            search_parts.append(f"({' '.join(clause_parts)})")
    
    # Combine based on condition
    if "and" in condition:
        search_combined = " ".join(search_parts)
    elif "or" in condition:
        search_combined = " OR ".join(search_parts)
    else:
        search_combined = search_parts[0] if search_parts else ""
    
    query = f'{source} {search_combined} | table _time, host, user, {_get_splunk_fields(category)}'
    
    return query, None


def _map_field_to_kusto(field: str) -> str:
    """Map Sigma field names to Kusto field names."""
    FIELD_MAP = {
        "Image": "InitiatingProcessFileName",
        "CommandLine": "ProcessCommandLine",
        "ParentImage": "InitiatingProcessParentFileName",
        "ParentCommandLine": "InitiatingProcessCommandLine",
        "User": "AccountName",
        "TargetFilename": "FileName",
        "DestinationIp": "RemoteIP",
        "DestinationPort": "RemotePort",
        "SourceIp": "LocalIP",
    }
    return FIELD_MAP.get(field, field)


def _map_field_to_splunk(field: str) -> str:
    """Map Sigma field names to Splunk field names."""
    FIELD_MAP = {
        "Image": "NewProcessName",
        "CommandLine": "CommandLine",
        "ParentImage": "ParentProcessName",
        "User": "SubjectUserName",
        "TargetFilename": "ObjectName",
    }
    return FIELD_MAP.get(field, field)


def _get_project_fields(category: str) -> str:
    """Get relevant fields to project based on log category."""
    CATEGORY_FIELDS = {
        "process_creation": "InitiatingProcessFileName, ProcessCommandLine, AccountName",
        "registry_event": "RegistryKey, RegistryValueName, RegistryValueData",
        "network_connection": "RemoteIP, RemotePort, InitiatingProcessFileName",
        "file_event": "FileName, FolderPath, InitiatingProcessFileName",
    }
    return CATEGORY_FIELDS.get(category, "DeviceName, ActionType")


def _get_splunk_fields(category: str) -> str:
    """Get relevant fields for Splunk based on log category."""
    CATEGORY_FIELDS = {
        "process_creation": "NewProcessName, CommandLine, SubjectUserName",
        "registry_event": "ObjectName, ObjectValueName",
        "network_connection": "DestAddress, DestPort, Application",
        "file_event": "ObjectName, SubjectUserName",
    }
    return CATEGORY_FIELDS.get(category, "EventCode, Message")


def convert_with_pysigma(rule_path: Path, target_format: str) -> tuple[Optional[str], Optional[str]]:
    """
    Convert a Sigma rule using official pySigma backends.
    
    This provides more accurate conversions than the native implementation.
    """
    try:
        from sigma.rule import SigmaRule
        from sigma.backends.kusto import KustoBackend
        from sigma.backends.splunk import SplunkBackend
        from sigma.pipelines.windows import windows_logsource_pipeline
        
        # Load and parse rule
        with open(rule_path, "r", encoding="utf-8") as f:
            rule_yaml = f.read()
        
        rule = SigmaRule.from_yaml(rule_yaml)
        
        # Select backend
        if target_format == "kusto":
            backend = KustoBackend()
        elif target_format == "splunk":
            backend = SplunkBackend()
        else:
            return None, f"Unsupported format: {target_format}"
        
        # Convert
        query = backend.convert_rule(rule)[0]
        return query, None
        
    except ImportError as e:
        return None, f"pySigma not available: {e}. Using native converter."
    except Exception as e:
        return None, f"Conversion failed: {e}"


def convert_rule_file(rule_path: Path, target_format: str, use_pysigma: bool = True) -> ConversionResult:
    """
    Convert a single Sigma rule file.
    
    Args:
        rule_path: Path to Sigma rule
        target_format: Target format (kusto, splunk)
        use_pysigma: Whether to use pySigma backends
        
    Returns:
        ConversionResult with query or error
    """
    # Load rule for metadata
    with open(rule_path, "r", encoding="utf-8") as f:
        rule = yaml.safe_load(f)
    
    rule_title = rule.get("title", rule_path.stem)
    
    # Try pySigma first, fall back to native
    if use_pysigma:
        query, error = convert_with_pysigma(rule_path, target_format)
        
        # Fall back to native if pySigma fails
        if error and "not available" in error:
            query, error = convert_rule_native(rule, target_format)
    else:
        query, error = convert_rule_native(rule, target_format)
    
    return ConversionResult(
        rule_path=str(rule_path),
        rule_title=rule_title,
        target_format=target_format,
        success=error is None,
        query=query,
        error=error,
    )


def convert_directory(rules_dir: Path, target_format: str, output_dir: Path) -> list[ConversionResult]:
    """
    Convert all Sigma rules in a directory.
    
    Args:
        rules_dir: Directory containing Sigma rules
        target_format: Target format
        output_dir: Directory to save converted rules
        
    Returns:
        List of ConversionResult objects
    """
    results = []
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # File extension based on format
    extensions = {"kusto": ".kql", "splunk": ".spl"}
    ext = extensions.get(target_format, ".txt")
    
    for rule_path in rules_dir.rglob("*.yml"):
        result = convert_rule_file(rule_path, target_format)
        results.append(result)
        
        # Save converted query if successful
        if result.success and result.query:
            output_file = output_dir / f"{rule_path.stem}{ext}"
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(f"// Rule: {result.rule_title}\n")
                f.write(f"// Source: {rule_path}\n\n")
                f.write(result.query)
    
    return results


def print_conversion_summary(results: list[ConversionResult]) -> bool:
    """
    Print a summary of conversion results.
    
    Returns:
        True if all conversions succeeded, False otherwise
    """
    success = sum(1 for r in results if r.success)
    failed = len(results) - success
    
    print(f"\n{'='*60}")
    print(f"Conversion Summary: {success} succeeded, {failed} failed")
    print(f"{'='*60}\n")
    
    for result in results:
        if result.success:
            print(f"✓ {result.rule_title}")
        else:
            print(f"✗ {result.rule_title}: {result.error}")
    
    return failed == 0
