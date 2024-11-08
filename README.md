# TermHound

A comprehensive Active Directory security analysis tool that integrates with Neo4j to detect vulnerabilities, analyze attack paths, and identify security misconfigurations.

## Features

- Certificate template vulnerability analysis (ESC1-ESC15)
- Kerberos security assessment
- Domain privilege escalation paths
- Attack path analysis from owned users
- Comprehensive security reporting
- Color-coded terminal output
- Detailed JSON reports

## Installation

1. Clone the repository
2. Install requirements:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

Basic usage:
```bash
python -m termhound --uri "neo4j://localhost:7687" \
    --username neo4j \
    --password your_password \
    --output report.json
```

With owned users:
```bash
python -m termhound  --uri "neo4j://localhost:7687" \
    --username neo4j \
    --password your_password \
    --output report.json \
    --owned "user1@domain.com" "user2@domain.com"
```

## Project Structure

```
termhound/
├── __init__.py
├── requirements.txt
├── README.md
└── src/
    ├── __init__.py
    ├── analyzer.py
    ├── reporters.py
    └── queries/
        ├── __init__.py
        ├── certificate_queries.py
        ├── domain_queries.py
        ├── kerberos_queries.py
        └── privilege_queries.py
```

## Requirements

- Python 3.8+
- Neo4j 4.4+
- BloodHound data imported into Neo4j
