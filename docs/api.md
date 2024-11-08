# TermHound API Documentation

## Core Classes

### TermHoundAnalyzer

Main analysis class that orchestrates security assessments.

```python
from termhound import TermHoundAnalyzer

analyzer = TermHoundAnalyzer(
    uri="neo4j://localhost:7687",
    username="neo4j",
    password="password",
    owned_users=["user@domain.com"]
)
```

#### Methods

- `analyze_domain_security()`: Domain-wide security analysis
- `analyze_certificate_security()`: Certificate template analysis
- `analyze_kerberos_security()`: Kerberos security analysis
- `analyze_attack_paths()`: Attack path discovery
- `generate_report(output_file)`: Generate comprehensive report

### Query Modules

#### CertificateQueries
```python
from termhound.queries import CertificateQueries

cert_queries = CertificateQueries(driver)
results = cert_queries.analyze_templates()
```

#### DomainQueries
```python
from termhound.queries import DomainQueries

domain_queries = DomainQueries(driver)
results = domain_queries.get_domain_info()
```

#### KerberosQueries
```python
from termhound.queries import KerberosQueries

kerberos_queries = KerberosQueries(driver)
results = kerberos_queries.analyze_asrep_roasting()
```

## Reporting Classes

### TerminalReporter
```python
from termhound.reporters import TerminalReporter

reporter = TerminalReporter()
reporter.print_finding("Critical Issue", ["Detail 1", "Detail 2"], "HIGH")
```

### JSONReporter
```python
from termhound.reporters import JSONReporter

reporter = JSONReporter()
reporter.generate_report(data, "output.json")
```

## Utility Functions

### Path Analysis
```python
from termhound.utils import format_path

formatted = format_path(path_data)
```

### Time Formatting
```python
from termhound.utils import format_timestamp

readable_time = format_timestamp(epoch_time)
```

## Configuration

### Loading Configuration
```python
from termhound.config import load_config

config = load_config("config.yaml")
```

## Examples

### Complete Analysis
```python
from termhound import TermHoundAnalyzer

analyzer = TermHoundAnalyzer(uri, username, password)

# Perform analysis
results = {
    'domain': analyzer.analyze_domain_security(),
    'certificates': analyzer.analyze_certificate_security(),
    'kerberos': analyzer.analyze_kerberos_security(),
    'paths': analyzer.analyze_attack_paths()
}

# Generate report
analyzer.generate_report("report.json")
```

### Custom Query Execution
```python
from termhound.queries import DomainQueries

domain_queries = DomainQueries(driver)
custom_query = """
    MATCH (n:User)
    WHERE n.enabled = true
    RETURN n
"""
results = domain_queries._execute_query(custom_query)
