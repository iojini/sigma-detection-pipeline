# Sigma Detection Pipeline

A Python-based detection engineering framework that validates, tests, and manages Sigma rules as code.

## Features

- **Rule Validator** — Validates Sigma rule syntax and required fields
- **Detection Tester** — Tests rules against log samples to verify they fire correctly
- **MITRE ATT&CK Coverage** — Generates coverage reports mapped to ATT&CK techniques
- **Format Converter** — Converts Sigma rules to KQL, Splunk SPL, and other formats
- **CI/CD Ready** — GitHub Actions workflow for automated validation on every PR

## Installation

```bash
git clone https://github.com/yourusername/sigma-detection-pipeline.git
cd sigma-detection-pipeline
pip install -r requirements.txt
```

## Usage

### Validate Rules

Check all rules for syntax errors and required fields:

```bash
python -m src.cli validate rules/
```

### Test Detections

Test rules against log samples to verify detection logic:

```bash
python -m src.cli test rules/ tests/log_samples/
```

### Generate Coverage Report

Generate a MITRE ATT&CK coverage report:

```bash
python -m src.cli coverage rules/ --output output/coverage.json
```

### Convert Rules

Convert Sigma rules to other query languages:

```bash
python -m src.cli convert rules/ --format kusto --output output/
```

## Project Structure

```
sigma-detection-pipeline/
├── src/
│   ├── __init__.py
│   ├── cli.py              # Command-line interface
│   ├── validator.py        # Rule validation logic
│   ├── tester.py           # Detection testing engine
│   ├── coverage.py         # MITRE ATT&CK coverage reporting
│   └── converter.py        # Format conversion (Sigma → KQL/SPL)
├── rules/                  # Custom Sigma detection rules
│   ├── execution/
│   ├── credential_access/
│   └── persistence/
├── tests/
│   ├── log_samples/        # Sample logs for testing detections
│   └── test_detections.py  # Unit tests
├── output/                 # Generated reports and converted rules
└── .github/workflows/      # CI/CD pipeline
```

## Writing Detection Rules

Rules follow the [Sigma specification](https://github.com/SigmaHQ/sigma-specification). Each rule should include:

- Clear title and description
- MITRE ATT&CK tags
- Detection logic with defined log source
- Documented false positives
- Severity level

See `rules/` for examples.

## MITRE ATT&CK Coverage

Current detection coverage:

| Tactic | Techniques Covered |
|--------|-------------------|
| Execution | T1059.001 |
| Credential Access | T1003.001 |
| Persistence | T1547.001 |

## Contributing

1. Create a new branch for your detection
2. Add your Sigma rule to the appropriate `rules/` subdirectory
3. Add corresponding log samples to `tests/log_samples/`
4. Run validation and tests locally
5. Open a PR — CI will automatically validate

## License

MIT
