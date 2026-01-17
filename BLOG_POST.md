# Building a Detection Engineering Pipeline: A Practical Guide

I built a Python-based pipeline that validates, tests, and manages Sigma detection rules. This post walks through my methodology.

## The Problem

Detection engineering teams face several challenges:
- Rules are often untested before deployment
- No easy way to track MITRE ATT&CK coverage
- Manual processes don't scale
- Lack of CI/CD for detection content

## My Solution

I built a command-line tool that treats detections as code:
```bash
# Validate rule syntax
python -m src.cli validate rules/

# Test against sample logs
python -m src.cli test rules/ tests/log_samples/

# Generate ATT&CK coverage report
python -m src.cli coverage-report rules/ --output coverage.json
```

## Architecture

The pipeline consists of four core modules:

| Module | Purpose |
|--------|---------|
| **validator.py** | Checks Sigma rule syntax and required fields |
| **tester.py** | Runs rules against log samples to verify detection logic |
| **coverage.py** | Maps rules to MITRE ATT&CK and generates reports |
| **converter.py** | Transforms Sigma to KQL/Splunk SPL |

## Detection Development Process

For each detection, I follow this methodology:

1. **Research the technique** — Read the ATT&CK page, find real-world examples
2. **Identify log sources** — What telemetry captures this behavior?
3. **Write the detection logic** — Start broad, then tune
4. **Create test cases** — Both malicious and benign samples
5. **Validate and test** — Run through the pipeline
6. **Document false positives** — Critical for operationalization

## Example: Detecting Encoded PowerShell

Attackers frequently use encoded PowerShell commands to evade detection. Here's my detection:
```yaml
detection:
    selection:
        Image|endswith: '\powershell.exe'
        CommandLine|contains:
            - '-enc'
            - '-EncodedCommand'
            - '-ec'
    condition: selection
```

**Why these indicators?**
- `-enc`, `-EncodedCommand`, `-ec` are all valid parameter shortcuts
- Legitimate encoded PowerShell exists but is relatively rare
- Combined with other signals, this provides good signal-to-noise

## Current Coverage

My detection pack covers 5 MITRE ATT&CK tactics:

| Tactic | Technique | Detection |
|--------|-----------|-----------|
| Execution | T1059.001 | Encoded PowerShell commands |
| Credential Access | T1003.001 | LSASS memory access |
| Persistence | T1547.001 | Registry Run key modifications |
| Discovery | T1087.001/002 | Account enumeration via net.exe |
| Defense Evasion | T1218.011 | Suspicious Rundll32 execution |

## CI/CD Integration

Every pull request triggers automated validation:

1. Syntax validation for all rules
2. Detection testing against sample logs
3. Coverage report generation

This ensures no broken rules reach production.

## Key Learnings

1. **Start with high-fidelity detections** — Better to have 5 solid rules than 50 noisy ones
2. **Test with realistic data** — Synthetic logs help validate logic before deployment
3. **Document everything** — False positives, tuning decisions, references
4. **Automate early** — CI/CD catches issues before they become problems

## What's Next

- Add more detection rules for lateral movement and exfiltration
- Integrate with MITRE ATT&CK Navigator for visualization
- Contribute rules to the SigmaHQ community repository

## Resources

- [Sigma Specification](https://github.com/SigmaHQ/sigma-specification)
- [MITRE ATT&CK](https://attack.mitre.org/)
- [My GitHub Repository](https://github.com/iojini/sigma-detection-pipeline)

---

*This project demonstrates practical detection engineering skills including rule development, testing methodology, and CI/CD automation.*
