"""
Sigma Detection Pipeline CLI

Command-line interface for validating, testing, and managing Sigma rules.
"""

import sys
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from . import validator
from . import tester
from . import coverage
from . import converter


console = Console()


@click.group()
@click.version_option(version="0.1.0")
def cli():
    """
    Sigma Detection Pipeline - Detection engineering as code.
    
    A toolkit for validating, testing, and managing Sigma detection rules.
    """
    pass


@cli.command()
@click.argument("rules_dir", type=click.Path(exists=True, path_type=Path))
@click.option("--strict", is_flag=True, help="Treat warnings as errors")
def validate(rules_dir: Path, strict: bool):
    """
    Validate Sigma rules for syntax and required fields.
    
    RULES_DIR: Directory containing Sigma rules (.yml files)
    """
    console.print(Panel.fit("🔍 Validating Sigma Rules", style="bold blue"))
    
    results = validator.validate_directory(rules_dir)
    
    if not results:
        console.print("[yellow]No Sigma rules found in directory[/yellow]")
        sys.exit(1)
    
    # Build results table
    table = Table(title="Validation Results")
    table.add_column("Status", style="bold")
    table.add_column("Rule")
    table.add_column("Issues")
    
    all_passed = True
    
    for result in results:
        if result.is_valid and (not strict or not result.warnings):
            status = "[green]✓ PASS[/green]"
        else:
            status = "[red]✗ FAIL[/red]"
            all_passed = False
        
        issues = []
        issues.extend([f"[red]ERROR: {e}[/red]" for e in result.errors])
        if strict:
            issues.extend([f"[yellow]WARN: {w}[/yellow]" for w in result.warnings])
        
        rule_name = Path(result.rule_path).name
        table.add_row(status, rule_name, "\n".join(issues) if issues else "-")
    
    console.print(table)
    
    # Summary
    passed = sum(1 for r in results if r.is_valid and (not strict or not r.warnings))
    console.print(f"\n[bold]Summary:[/bold] {passed}/{len(results)} rules passed")
    
    sys.exit(0 if all_passed else 1)


@cli.command()
@click.argument("rules_dir", type=click.Path(exists=True, path_type=Path))
@click.argument("logs_dir", type=click.Path(exists=True, path_type=Path))
@click.option("--verbose", "-v", is_flag=True, help="Show matched log details")
def test(rules_dir: Path, logs_dir: Path, verbose: bool):
    """
    Test Sigma rules against log samples.
    
    RULES_DIR: Directory containing Sigma rules
    
    LOGS_DIR: Directory containing log samples (JSON format)
    """
    console.print(Panel.fit("🧪 Testing Detections", style="bold blue"))
    
    results = tester.test_directory(rules_dir, logs_dir)
    
    if not results:
        console.print("[yellow]No rules or logs found to test[/yellow]")
        sys.exit(1)
    
    # Build results table
    table = Table(title="Detection Test Results")
    table.add_column("Status", style="bold")
    table.add_column("Rule")
    table.add_column("Matches")
    
    for result in results:
        if result.fired:
            status = "[green]✓ FIRED[/green]"
        else:
            status = "[red]✗ NO MATCH[/red]"
        
        table.add_row(status, result.rule_title, f"{result.matches}/{result.total_logs}")
        
        if verbose and result.matched_logs:
            for log in result.matched_logs[:3]:  # Show first 3 matches
                console.print(f"  [dim]→ {log}[/dim]")
    
    console.print(table)
    
    # Summary
    fired = sum(1 for r in results if r.fired)
    console.print(f"\n[bold]Summary:[/bold] {fired}/{len(results)} detections fired")
    
    sys.exit(0 if fired > 0 else 1)


@cli.command()
@click.argument("rules_dir", type=click.Path(exists=True, path_type=Path))
@click.option("--output", "-o", type=click.Path(path_type=Path), default="coverage.json",
              help="Output file path for coverage report")
@click.option("--navigator", is_flag=True, help="Also generate ATT&CK Navigator layer")
def coverage_report(rules_dir: Path, output: Path, navigator: bool):
    """
    Generate MITRE ATT&CK coverage report.
    
    RULES_DIR: Directory containing Sigma rules
    """
    console.print(Panel.fit("📊 Generating Coverage Report", style="bold blue"))
    
    report = coverage.analyze_rules_directory(rules_dir)
    
    # Build summary table
    table = Table(title="MITRE ATT&CK Coverage")
    table.add_column("Metric", style="bold")
    table.add_column("Value")
    
    table.add_row("Total Rules", str(report.total_rules))
    table.add_row("Rules with ATT&CK Tags", str(report.rules_with_tags))
    table.add_row("Techniques Covered", str(len(report.techniques_covered)))
    table.add_row("Tactics Covered", str(len(report.tactics_covered)))
    
    console.print(table)
    
    # Tactics breakdown
    if report.tactics_covered:
        tactics_table = Table(title="Coverage by Tactic")
        tactics_table.add_column("Tactic")
        tactics_table.add_column("Techniques")
        
        for tactic, techniques in sorted(report.tactics_covered.items()):
            tactics_table.add_row(
                tactic.replace("_", " ").title(),
                ", ".join(t.upper() for t in techniques)
            )
        
        console.print(tactics_table)
    
    # Save report
    output.parent.mkdir(parents=True, exist_ok=True)
    coverage.save_report(report, output, include_navigator=navigator)
    
    console.print(f"\n[green]✓ Coverage report saved to {output}[/green]")
    
    if navigator:
        nav_path = output.with_name(f"{output.stem}_navigator.json")
        console.print(f"[green]✓ ATT&CK Navigator layer saved to {nav_path}[/green]")


@cli.command()
@click.argument("rules_dir", type=click.Path(exists=True, path_type=Path))
@click.option("--format", "-f", "target_format", type=click.Choice(["kusto", "splunk"]),
              default="kusto", help="Target query language")
@click.option("--output", "-o", type=click.Path(path_type=Path), default="output",
              help="Output directory for converted rules")
def convert(rules_dir: Path, target_format: str, output: Path):
    """
    Convert Sigma rules to SIEM query language.
    
    RULES_DIR: Directory containing Sigma rules
    """
    console.print(Panel.fit(f"🔄 Converting to {target_format.upper()}", style="bold blue"))
    
    results = converter.convert_directory(rules_dir, target_format, output)
    
    if not results:
        console.print("[yellow]No Sigma rules found to convert[/yellow]")
        sys.exit(1)
    
    # Build results table
    table = Table(title="Conversion Results")
    table.add_column("Status", style="bold")
    table.add_column("Rule")
    table.add_column("Details")
    
    for result in results:
        if result.success:
            status = "[green]✓ OK[/green]"
            details = f"Saved to {output}/{Path(result.rule_path).stem}.kql"
        else:
            status = "[red]✗ FAIL[/red]"
            details = result.error or "Unknown error"
        
        table.add_row(status, result.rule_title, details)
    
    console.print(table)
    
    # Summary
    success = sum(1 for r in results if r.success)
    console.print(f"\n[bold]Summary:[/bold] {success}/{len(results)} rules converted")
    console.print(f"[green]✓ Converted rules saved to {output}/[/green]")
    
    sys.exit(0 if success == len(results) else 1)


@cli.command()
@click.argument("rules_dir", type=click.Path(exists=True, path_type=Path))
@click.argument("logs_dir", type=click.Path(exists=True, path_type=Path))
@click.option("--output", "-o", type=click.Path(path_type=Path), default="output",
              help="Output directory for reports")
def full_pipeline(rules_dir: Path, logs_dir: Path, output: Path):
    """
    Run full pipeline: validate, test, and generate coverage.
    
    RULES_DIR: Directory containing Sigma rules
    
    LOGS_DIR: Directory containing log samples
    """
    console.print(Panel.fit("🚀 Running Full Pipeline", style="bold magenta"))
    
    output.mkdir(parents=True, exist_ok=True)
    
    # Step 1: Validate
    console.print("\n[bold]Step 1: Validation[/bold]")
    val_results = validator.validate_directory(rules_dir)
    passed = sum(1 for r in val_results if r.is_valid)
    console.print(f"  {passed}/{len(val_results)} rules passed validation")
    
    # Step 2: Test
    console.print("\n[bold]Step 2: Testing[/bold]")
    test_results = tester.test_directory(rules_dir, logs_dir)
    fired = sum(1 for r in test_results if r.fired)
    console.print(f"  {fired}/{len(test_results)} detections fired")
    
    # Step 3: Coverage
    console.print("\n[bold]Step 3: Coverage Analysis[/bold]")
    cov_report = coverage.analyze_rules_directory(rules_dir)
    console.print(f"  {len(cov_report.techniques_covered)} techniques covered")
    
    coverage_path = output / "coverage.json"
    coverage.save_report(cov_report, coverage_path, include_navigator=True)
    
    # Final summary
    console.print(Panel.fit(
        f"[green]✓ Pipeline complete![/green]\n\n"
        f"Validation: {passed}/{len(val_results)} passed\n"
        f"Testing: {fired}/{len(test_results)} fired\n"
        f"Coverage: {len(cov_report.techniques_covered)} techniques\n\n"
        f"Reports saved to {output}/",
        title="Summary",
        style="bold green"
    ))


def main():
    """Entry point for the CLI."""
    cli()


if __name__ == "__main__":
    main()
