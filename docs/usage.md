# TermHound Usage Guide

## Basic Usage

### Command Line Interface

Basic scan:
```bash
termhound --uri neo4j://localhost:7687 \
          --username neo4j \
          --password your_password \
          --output report.json
```

With owned users:
```bash
termhound --uri neo4j://localhost:7687 \
          --username neo4j \
          --password your_password \
          --output report.json \
          --owned "user1@domain.com" "user2@domain.com"
```

### Configuration File

Using a config file:
```bash
termhound --config config.yaml --output report.json
```

## Advanced Usage

### Attack Path Analysis

1. Find paths to Domain Admin:
```bash
termhound --mode paths --target "Domain Admins"
```

2. Analyze specific user's privileges:
```bash
termhound --mode user-analysis --user "username@domain.com"
```

3. Certificate template analysis:
```bash
termhound --mode certificates
```

### Reporting Options

1. Generate JSON report:
```bash
termhound --output report.json
```

2. Generate HTML report:
```bash
termhound --output report.html --format html
```

3. Terminal-only output:
```bash
termhound --no-report
```

## Query Examples

### Domain Enumeration
```cypher
MATCH (n:Domain) RETURN n
```

### Find Kerberoastable Users
```cypher
MATCH (u:User {hasspn:true}) RETURN u
```

### Path to Domain Admin
```cypher
MATCH p=shortestPath((u:User)-[*1..]->(g:Group))
WHERE g.name CONTAINS 'DOMAIN ADMINS'
RETURN p
```

## Best Practices

1. Regular Scanning:
   - Schedule periodic scans
   - Monitor for changes
   - Track improvements

2. Data Management:
   - Regular BloodHound data collection
   - Keep Neo4j database updated
   - Archive reports

3. Security Considerations:
   - Use dedicated service accounts
   - Implement least privilege
   - Monitor tool usage
