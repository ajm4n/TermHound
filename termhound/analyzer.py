#!/usr/bin/env python3
from typing import Dict, List, Optional, Any
from datetime import datetime
import logging
import json
import sys
import argparse
from pathlib import Path
from neo4j import GraphDatabase
from .reporters import TerminalReporter, JSONReporter
from .queries import (
    CertificateQueries,
    DomainQueries,
    KerberosQueries,
    PrivilegeQueries
)
from .parsers.bloodhound_parser import BloodHoundParser
from colorama import init, Fore, Style

init()

class TermHoundAnalyzer:
    def __init__(self, source_type: str = "neo4j", **kwargs):
        """Initialize TermHound analyzer
        
        Args:
            source_type: "neo4j" or "bloodhound"
            **kwargs: 
                For neo4j: uri, username, password, owned_users, debug
                For bloodhound: zip_path, owned_users, debug
        """
        # Set debug first so logging can use it
        self.debug = kwargs.get('debug', False)
        self.logger = self._setup_logging()
        self.source_type = source_type
        self.owned_users = kwargs.get('owned_users', [])
        self.terminal_reporter = TerminalReporter()
        self.json_reporter = JSONReporter()
        
        if source_type == "neo4j":
            if not all(k in kwargs for k in ['uri', 'username', 'password']):
                raise ValueError("Neo4j source requires uri, username, and password")
            
            self.driver = GraphDatabase.driver(
                kwargs['uri'], 
                auth=(kwargs['username'], kwargs['password'])
            )
            # Initialize query modules
            self.cert_queries = CertificateQueries(self.driver)
            self.domain_queries = DomainQueries(self.driver)
            self.kerberos_queries = KerberosQueries(self.driver)
            self.privilege_queries = PrivilegeQueries(self.driver)
        
        elif source_type == "bloodhound":
            if 'zip_path' not in kwargs:
                raise ValueError("BloodHound source requires zip_path")
            
            self.zip_path = kwargs['zip_path']
            if not Path(self.zip_path).exists():
                raise FileNotFoundError(f"BloodHound zip file not found: {self.zip_path}")
                
            self.bloodhound_parser = BloodHoundParser(debug=self.debug)
            self.bloodhound_data = None
        
        else:
            raise ValueError(f"Invalid source type: {source_type}")
            
        self.logger.info(f"Initialized TermHound with {source_type} source")
        if self.debug:
            self.logger.debug(f"Debug mode enabled")
            self.logger.debug(f"Initialization parameters: {kwargs}")

    def _setup_logging(self) -> logging.Logger:
        """Setup logging configuration"""
        logger = logging.getLogger('TermHound')
        logger.handlers = []
        logger.setLevel(logging.DEBUG if self.debug else logging.INFO)
        
        # Create handlers
        c_handler = logging.StreamHandler(sys.stdout)
        f_handler = logging.FileHandler(f'termhound_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log')
        
        # Create formatters and add to handlers
        c_format = logging.Formatter('%(levelname)s: %(message)s')
        f_format = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        c_handler.setFormatter(c_format)
        f_handler.setFormatter(f_format)
        
        # Add handlers to the logger
        logger.addHandler(c_handler)
        logger.addHandler(f_handler)
        
        return logger

    def analyze(self) -> Dict[str, Any]:
        """Perform comprehensive security analysis"""
        try:
            self.logger.info(f"Starting analysis using {self.source_type} source")
            
            if self.source_type == "neo4j":
                results = self._analyze_neo4j()
            else:
                results = self._analyze_bloodhound()
                
            # Generate reports
            self.terminal_reporter.generate_report(results)
            return results
            
        except Exception as e:
            self.logger.error(f"Analysis failed: {str(e)}")
            raise

    def _check_neo4j_connection(self) -> bool:
        """Test Neo4j connection"""
        try:
            with self.driver.session() as session:
                result = session.run("RETURN 1 as test")
                return result.single()['test'] == 1
        except Exception as e:
            self.logger.error(f"Neo4j connection test failed: {str(e)}")
            return False
    def _analyze_neo4j(self) -> Dict[str, Any]:
        """Analyze data from Neo4j database"""
        try:
            # Test connection
            if not self._check_neo4j_connection():
                raise ConnectionError("Could not connect to Neo4j database")

            # Mark owned users if specified
            if self.owned_users:
                self.logger.info(f"Marking owned users: {self.owned_users}")
                self.domain_queries.mark_owned_users(self.owned_users)
            
            self.logger.info("Starting Neo4j analysis")
            
            results = {
                'timestamp': datetime.now().isoformat(),
                'metadata': {
                    'source': 'neo4j',
                    'owned_users': self.owned_users,
                    'analysis_date': datetime.now().isoformat()
                },
                'domain_security': {
                    'info': self.domain_queries.get_domain_info(),
                    'vulnerabilities': self.domain_queries.get_vulnerabilities(),
                    'critical_assets': self.domain_queries.get_critical_assets(),
                    'privileged_accounts': self.domain_queries.get_privileged_accounts()
                },
                'certificate_security': {
                    'templates': self.cert_queries.analyze_templates(),
                    'authorities': self.cert_queries.analyze_authorities(),
                    'vulnerabilities': self.cert_queries.get_vulnerabilities(),
                    'esc_findings': self.cert_queries.analyze_esc_vulnerabilities()
                },
                'kerberos_security': {
                    'as_rep': self.kerberos_queries.analyze_asrep_roasting(),
                    'spn': self.kerberos_queries.analyze_kerberoasting(),
                    'delegations': self.kerberos_queries.analyze_delegations(),
                    'high_risk': self.kerberos_queries.get_high_risk_accounts()
                },
                'attack_paths': {
                    'domain_admin': self.privilege_queries.find_paths_to_da(),
                    'high_value': self.privilege_queries.find_paths_to_high_value(),
                    'owned_paths': self.privilege_queries.find_paths_from_owned() if self.owned_users else {}
                }
            }
            
            return results
            
        except Exception as e:
            self.logger.error(f"Error in Neo4j analysis: {str(e)}")
            raise

    def _analyze_bloodhound(self) -> Dict[str, Any]:
        """Analyze data from BloodHound zip file"""
        try:
            self.logger.info(f"Starting BloodHound analysis from {self.zip_path}")
            
            # Parse BloodHound data if not already parsed
            if not self.bloodhound_data:
                self.logger.info("Parsing BloodHound data")
                self.bloodhound_data = self.bloodhound_parser.parse_zip(self.zip_path)

            # Mark owned users if specified
            if self.owned_users:
                self.logger.info(f"Marking owned users: {self.owned_users}")
                self._mark_owned_in_bloodhound()

            # Get main analysis results
            analysis = self.bloodhound_parser.analyze_data()
            
            results = {
                'timestamp': datetime.now().isoformat(),
                'metadata': {
                    'source': 'bloodhound',
                    'owned_users': self.owned_users,
                    'analysis_date': datetime.now().isoformat(),
                    'file': self.zip_path
                },
                'domain_security': {
                    'info': analysis['summary'],
                    'vulnerabilities': analysis['security_findings'],
                    'critical_assets': self._get_critical_assets_from_bloodhound(),
                    'privileged_accounts': analysis['privileged_accounts']
                },
                'certificate_security': {
                    'templates': analysis['certificate_analysis'].get('vulnerable_templates', []),
                    'authorities': analysis['certificate_analysis'].get('misconfigured_cas', [])
                },
                'kerberos_security': self._analyze_kerberos_from_bloodhound(),
                'attack_paths': self._analyze_paths_from_bloodhound()
            }

            self.logger.info("BloodHound analysis completed successfully")
            return results

        except Exception as e:
            self.logger.error(f"Error in BloodHound analysis: {str(e)}")
            raise

    def _mark_owned_in_bloodhound(self):
        """Mark owned users in BloodHound data"""
        marked_count = 0
        for user in self.bloodhound_data['users']:
            props = user.get('Properties', {})
            name = props.get('name', '')
            if name in self.owned_users:
                props['owned'] = True
                marked_count += 1
        
        self.logger.info(f"Marked {marked_count} users as owned")

    def _get_critical_assets_from_bloodhound(self) -> Dict[str, Any]:
        """Extract critical assets from BloodHound data"""
        critical_assets = {
            'domain_controllers': [],
            'high_value_targets': []
        }
        
        # Find Domain Controllers
        for computer in self.bloodhound_data.get('computers', []):
            props = computer.get('Properties', {})
            if props.get('primarygroup', '').endswith('-516'):  # Domain Controllers group
                critical_assets['domain_controllers'].append(props.get('name', ''))

        # Find high-value targets
        for obj in self.bloodhound_data.get('groups', []):
            props = obj.get('Properties', {})
            sid = props.get('objectid', '')
            if any(sid.endswith(s) for s in ['-512', '-519', '-544']):  # Admin groups
                critical_assets['high_value_targets'].append(props.get('name', ''))

        self.logger.info(f"Found {len(critical_assets['domain_controllers'])} domain controllers and {len(critical_assets['high_value_targets'])} high-value targets")
        return critical_assets

    def _analyze_kerberos_from_bloodhound(self) -> Dict[str, Any]:
        """Analyze Kerberos security from BloodHound data"""
        kerberos_info = {
            'as_rep': [],
            'spn': [],
            'delegations': [],
            'high_risk': []
        }
        
        for user in self.bloodhound_data.get('users', []):
            props = user.get('Properties', {})
            name = props.get('name')
            
            if not name:
                continue
                
            # AS-REP Roasting
            if props.get('dontreqpreauth', False):
                kerberos_info['as_rep'].append(name)
                kerberos_info['high_risk'].append({
                    'name': name,
                    'type': 'AS-REP Roasting'
                })
                
            # Kerberoasting
            if props.get('hasspn', False):
                kerberos_info['spn'].append(name)
                kerberos_info['high_risk'].append({
                    'name': name,
                    'type': 'Kerberoastable'
                })
                
            # Delegation
            if props.get('allowedtodelegate') or props.get('unconstraineddelegation'):
                kerberos_info['delegations'].append(name)
                kerberos_info['high_risk'].append({
                    'name': name,
                    'type': 'Delegation'
                })

        self.logger.info(f"Found {len(kerberos_info['high_risk'])} Kerberos-related risks")
        return kerberos_info

    def _analyze_paths_from_bloodhound(self) -> Dict[str, Any]:
        """Analyze attack paths from BloodHound data"""
        paths = {
            'domain_admin': [],
            'high_value': [],
            'owned_paths': []
        }
        
        # Get paths to domain admin groups
        admin_sids = ['-512', '-519', '-544']  # Domain Admins, Enterprise Admins, Administrators
        for rel in self.bloodhound_data.get('relationships', []):
            end_node = rel.get('EndNode', '')
            if any(end_node.endswith(sid) for sid in admin_sids):
                paths['domain_admin'].append({
                    'start': rel.get('StartNode'),
                    'end': end_node,
                    'type': rel.get('RelationshipType')
                })

        # If we have owned users, get their paths
        if self.owned_users:
            for rel in self.bloodhound_data.get('relationships', []):
                start_props = self._get_node_props(rel.get('StartNode'))
                if start_props.get('owned', False):
                    paths['owned_paths'].append({
                        'start': rel.get('StartNode'),
                        'end': rel.get('EndNode'),
                        'type': rel.get('RelationshipType')
                    })

        self.logger.info(f"Found {len(paths['domain_admin'])} paths to Domain Admin")
        self.logger.info(f"Found {len(paths['owned_paths'])} paths from owned users")
        return paths

    def _get_node_props(self, node_id: str) -> Dict:
        """Get properties for a node by ID from BloodHound data"""
        if not node_id:
            return {}
            
        for obj_type in ['users', 'computers', 'groups']:
            for obj in self.bloodhound_data.get(obj_type, []):
                if obj.get('ObjectIdentifier') == node_id:
                    return obj.get('Properties', {})
        return {}

    def close(self):
        """Close any open connections"""
        if self.source_type == "neo4j" and hasattr(self, 'driver'):
            self.driver.close()
            self.logger.info("Closed Neo4j connection")

def main():
    parser = argparse.ArgumentParser(description='TermHound - AD Security Analysis Tool')
    
    # Add source type argument
    parser.add_argument('--source', choices=['neo4j', 'bloodhound'], required=True,
                      help='Data source type (neo4j or bloodhound)')

    # Source-specific arguments
    neo4j_group = parser.add_argument_group('Neo4j options')
    neo4j_group.add_argument('--uri', help='Neo4j database URI')
    neo4j_group.add_argument('--username', help='Neo4j username')
    neo4j_group.add_argument('--password', help='Neo4j password')
    
    bloodhound_group = parser.add_argument_group('BloodHound options')
    bloodhound_group.add_argument('--zip', help='Path to BloodHound zip file')
    
    # Common arguments
    parser.add_argument('--output', required=True, help='Output report file')
    parser.add_argument('--owned', nargs='+', help='List of owned usernames')
    parser.add_argument('--debug', action='store_true', help='Enable debug output')
    
    args = parser.parse_args()
    
    try:
        kwargs = {
            'debug': args.debug,
            'owned_users': args.owned
        }
        
        if args.source == 'neo4j':
            if not all([args.uri, args.username, args.password]):
                print(f"{Fore.RED}Error: Neo4j source requires --uri, --username, and --password{Style.RESET_ALL}")
                sys.exit(1)
            kwargs.update({
                'uri': args.uri,
                'username': args.username,
                'password': args.password
            })
        else:  # bloodhound
            if not args.zip:
                print(f"{Fore.RED}Error: BloodHound source requires --zip{Style.RESET_ALL}")
                sys.exit(1)
            kwargs['zip_path'] = args.zip

        analyzer = TermHoundAnalyzer(source_type=args.source, **kwargs)
        results = analyzer.analyze()
        
        # Save JSON report
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2, default=str)
            
        print(f"\n{Fore.GREEN}Analysis complete! Report saved to: {args.output}{Style.RESET_ALL}")
        analyzer.close()
        
    except Exception as e:
        print(f"{Fore.RED}Error during analysis: {str(e)}{Style.RESET_ALL}")
        sys.exit(1)

if __name__ == "__main__":
    main()