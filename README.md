
# IOC Extractor

A Python-based Indicators of Compromise (IOC) extraction tool designed to identify and analyze potential security indicators from log files.

The tool extracts IPv4 addresses, domains, URLs, and file hashes from security logs, classifies IP addresses, displays frequency statistics, and generates structured JSON reports.

## Features

- **IPv4 Extraction:** Identifies and validates IPv4 addresses.
- **IP Classification:** Categorizes addresses as public, private, loopback, multicast, link-local, reserved, or unspecified.
- **Domain Extraction:** Identifies domain-like indicators using a basic TLD allowlist.
- **URL Extraction:** Detects HTTP and HTTPS URLs.
- **Hash Extraction:** Identifies MD5, SHA1, and SHA256 hashes.
- **Frequency Analysis:** Displays occurrence counts and the most frequently observed indicators.
- **Multiple Log Sources:** Supports historical SSH logs, local system journal snapshots, and custom log files.
- **JSON Reporting:** Exports extracted indicators, statistics, and analysis metadata.
- **Unit Testing:** Includes automated tests for core extraction and reporting functions.

## Project Structure

```text
day05-ioc-extractor/
├── src/
│   └── ioc_extractor.py
├── sample_data/
│   └── security.log
├── tests/
│   └── test_ioc_extractor.py
├── data/
│   ├── local_logs/       # Excluded from Git
│   └── real_logs/        # Excluded from Git
├── output/               # Excluded from Git
├── .gitignore
└── README.md
```

## Requirements

- Python 3.10 or newer
- Linux, macOS, or Windows with Python installed
- No third-party Python packages required

## Getting Started

Clone the repository:

```bash
git clone https://github.com/YOUR_USERNAME/day05-ioc-extractor.git
cd day05-ioc-extractor
```

No external Python dependencies are required.

## Usage

### 1. Analyze the historical SSH dataset

```bash
python src/ioc_extractor.py --source historical
```

### 2. Analyze a local system journal snapshot

```bash
python src/ioc_extractor.py --source local
```

The local source expects a snapshot at:

```text
data/local_logs/system-journal.log
```

You can create one on a system using systemd:

```bash
journalctl --since today --no-pager -o short-iso > data/local_logs/system-journal.log
```

### 3. Analyze a custom log file

```bash
python src/ioc_extractor.py --log sample_data/security.log
```

### 4. Generate a JSON report

Historical dataset:

```bash
python src/ioc_extractor.py --source historical --report output/historical-report.json
```

Local journal snapshot:

```bash
python src/ioc_extractor.py --source local --report output/local-report.json
```

Custom log:

```bash
python src/ioc_extractor.py --log sample_data/security.log --report output/custom-report.json
```

### 5. View available arguments

```bash
python src/ioc_extractor.py --help
```

## Example Analysis

The historical SSH dataset used during development contained:

| Metric | Result |
|---|---:|
| Log lines processed | 655,147 |
| IPv4 occurrences | 549,465 |
| Unique IPv4 addresses | 1,242 |
| Domain-like occurrences | 10,132 |
| Unique domain-like indicators | 268 |
| URL occurrences | 0 |
| Hash occurrences | 0 |

These figures describe the analyzed historical dataset and are not current threat intelligence.

## JSON Report

The optional JSON report contains:

- Report generation timestamp
- Source log filename
- Summary statistics
- IP address classifications
- Extracted IPv4 addresses
- Extracted domains
- Extracted URLs
- Extracted file hashes
- Analysis disclaimer

Generated reports are stored in the `output/` directory, which is excluded from version control.

## Running Tests

Run the automated test suite:

```bash
python -m unittest discover -s tests -v
```

The test suite covers:

- Valid and invalid IPv4 extraction
- Domain extraction
- URL extraction
- Hash extraction
- IP classification
- Log analysis
- JSON report generation

**Current test status: 8 tests passing.**

## Limitations

- Extracted indicators are candidates and are not automatically confirmed as malicious.
- No threat-intelligence feeds or reputation services are integrated.
- Domain extraction uses a basic TLD allowlist and may miss valid domains or identify false positives.
- URL extraction uses pattern matching and does not perform complete URL validation.
- IP classification is a basic categorization, not a full network intelligence assessment.
- Local journal analysis processes a static snapshot, not a live monitoring stream.
- The historical SSH dataset represents older activity and should not be treated as current threat intelligence.

## Security and Privacy

- Local system logs and downloaded datasets are excluded from Git tracking.
- Generated reports are excluded from Git tracking.
- Avoid publishing raw logs because they may contain usernames, hostnames, IP addresses, system identifiers, or other sensitive information.
- Use the tool only on logs and systems you are authorized to analyze.

## Disclaimer

This project is developed for educational and cybersecurity research purposes. Extracted indicators are not proof of malicious activity. Further investigation and threat-intelligence validation are required before classifying an indicator as malicious.

## Author

Developed as part of a hands-on cybersecurity portfolio project focused on security log analysis and SOC-related skills.

