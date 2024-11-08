#!/usr/bin/env python3
from typing import Dict, List, Optional, Any
from datetime import datetime
import logging
import json
from neo4j import GraphDatabase
from .reporters import TerminalReporter, JSONReporter
from .queries import (
    CertificateQueries,
    DomainQueries,
    KerberosQueries,
    PrivilegeQueries
)

class TermHoundAnalyzer:
    def __init__(self, uri: str, username: str, password: str, owned_users: List[str] = None):
        """Initialize TermHound analyzer"""
        self.driver = GraphDatabase.driver(uri, auth=(username, password))
        self.logger = self._setup_logging()
        self.terminal_reporter = TerminalReporter()
        self.json_reporter = JSONReporter()
        self.owned_users = owned_users or []
        
        # Initialize query modules
        self.cert_queries = CertificateQueries(self.driver)
        self.domain_queries = DomainQueries(self.driver)
        self.kerberos_queries = KerberosQueries(self.driver)
        self.privilege_queries = PrivilegeQueries(self.driver)

    def _setup_logging(self) -> logging.Logger:
        """Setup logging configuration"""
        logger = logging.getLogger('TermHound')
        logger.setLevel(logging.INFO)
        
        fh = logging.FileHandler(
            f'termhound_analysis_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'
        )
        fh.setLevel(logging.INFO)
        
        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO)
        
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        fh.setFormatter(formatter)
        ch.setFormatter(formatter)
        
        logger.addHandler(fh)
        logger.addHandler(ch)
        
        return logger

    def mark_owned_users(self) -> List[Dict]:
        """Mark specified users as owned in the database"""
        return self.domain_queries.mark_owned_users(self.owned_users)

    def analyze_domain_security(self) -> Dict[str, Any]:
        """Perform comprehensive domain security analysis"""
        return {
            'info': self.domain_queries.get_domain_info(),
            'vulnerabilities': self.domain_queries.get_vulnerabilities(),
            'critical_assets': self.domain_queries.get_critical_assets(),
            'privileged_accounts': self.domain_queries.get_privileged_accounts()
        }

    def analyze_certificate_security(self) -> Dict[str, Any]:
        """Analyze certificate-related security issues"""
        return {
            'templates': self.cert_queries.analyze_templates(),
            'authorities': self.cert_queries.analyze_authorities(),
            'vulnerabilities': self.cert_queries.get_vulnerabilities(),
            'esc_findings': self.cert_queries.analyze_esc_vulnerabilities()
        }

    def analyze_kerberos_security(self) -> Dict[str, Any]:
        """Analyze Kerberos-related security issues"""
        return {
            'as_rep': self.kerberos_queries.analyze_asrep_roasting(),
            'spn': self.kerberos_queries.analyze_kerberoasting(),
            'delegations': self.kerberos_queries.analyze_delegations(),
            'high_risk': self.kerberos_queries.get_high_risk_accounts()
        }

    def analyze_attack_paths(self) -> Dict[str, Any]:
        """Analyze attack paths in the domain"""
        return {
            'domain_admin': self.privilege_queries.find_paths_to_da(),
            'high_value': self.privilege_queries.find_paths_to_high_value(),
            'owned_paths': self.privilege_queries.find_paths_from_owned() if self.owned_users else {}
        }

    def generate_report(self, output_file: str):
        """Generate comprehensive security analysis report"""
        if self.owned_users:
            self.mark_owned_users()
            
        report = {
            'timestamp': datetime.now().isoformat(),
            'metadata': {
                'owned_users': self.owned_users,
                'analysis_date': datetime.now().isoformat()
            },
            'domain_security': self.analyze_domain_security(),
            'certificate_security': self.analyze_certificate_security(),
            'kerberos_security': self.analyze_kerberos_security(),
            'attack_paths': self.analyze_attack_paths()
        }

        # Generate terminal report
        self.terminal_reporter.generate_report(report)

        # Save JSON report
        self.json_reporter.generate_report(report, output_file)
        self.logger.info(f"Report generated successfully: {output_file}")

    def close(self):
        """Close the Neo4j connection"""
        self.driver.close()

def main():
    import argparse

    parser = argparse.ArgumentParser(description='TermHound - AD Security Analysis Tool')
    parser.add_argument('--uri', required=True, help='Neo4j database URI')
    parser.add_argument('--username', required=True, help='Neo4j username')
    parser.add_argument('--password', required=True, help='Neo4j password')
    parser.add_argument('--output', required=True, help='Output report file')
    parser.add_argument('--owned', nargs='+', help='List of owned usernames')
    parser.add_argument('--quiet', action='store_true', help='Suppress terminal output')
    
    args = parser.parse_args()
    
    try:
        analyzer = TermHoundAnalyzer(
            args.uri, 
            args.username, 
            args.password,
            args.owned
        )
        
        analyzer.generate_report(args.output)
        analyzer.close()
        
    except Exception as e:
        print(f"Error during analysis: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
