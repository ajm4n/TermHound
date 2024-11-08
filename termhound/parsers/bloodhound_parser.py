import json
import zipfile
from typing import Dict, List, Any, Set
from pathlib import Path
import logging
import sys
from colorama import Fore, Style
import re
from datetime import datetime

class BloodHoundParser:
    """Parser for BloodHound collection data"""
    
    def __init__(self, debug: bool = False):
        """Initialize the BloodHound parser"""
        self.logger = logging.getLogger('TermHound.Parser')
        self.debug = debug
        self._setup_logging()
        self.reset_data()
        
        # Define standard SIDs for privileged groups
        self.PRIVILEGED_SIDS = {
            "-512": "Domain Admins",
            "-519": "Enterprise Admins",
            "-544": "Administrators",
            "-551": "Backup Operators",
            "-548": "Account Operators",
            "-526": "Key Admins",
            "-527": "Enterprise Key Admins",
            "-525": "Protected Users"
        }
        
        # Define high-risk rights
        self.HIGH_RISK_RIGHTS = {
            "GenericAll", "GenericWrite", "WriteDacl", "WriteOwner",
            "AddMember", "ForceChangePassword", "AllExtendedRights"
        }

    def reset_data(self):
        """Reset internal data structures"""
        self._data = {
            'computers': [],
            'users': [],
            'groups': [],
            'domains': [],
            'gpos': [],
            'ous': [],
            'certificate_templates': [],
            'enterprise_cas': [],
            'root_cas': [],
            'ntauth_store': [],
            'relationships': [],
            'containers': [],
            'aia_cas': [],
            'meta': {
                'collected': datetime.now().isoformat(),
                'processed': 0,
                'errors': 0,
                'skipped': 0
            }
        }
        self._stats = {
            'processed_files': 0,
            'errors': 0,
            'skipped': 0,
            'relationships_count': 0,
            'objects_count': 0
        }
        self._processed_nodes: Set[str] = set()

    def _setup_logging(self):
        """Setup logging configuration"""
        handler = logging.StreamHandler(sys.stdout)
        formatter = logging.Formatter('%(levelname)s: %(message)s')
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
        self.logger.setLevel(logging.DEBUG if self.debug else logging.INFO)

    def parse_zip(self, zip_path: str) -> Dict[str, Any]:
        """Parse BloodHound data from zip file"""
        try:
            self.logger.info(f"Processing BloodHound zip file: {zip_path}")
            self.reset_data()
            
            if not Path(zip_path).exists():
                raise FileNotFoundError(f"Zip file not found: {zip_path}")

            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                json_files = [f for f in zip_ref.namelist() if f.endswith('.json')]
                self.logger.info(f"Found {len(json_files)} JSON files in zip")
                
                # Process each file
                for filename in json_files:
                    self.logger.info(f"Processing {filename}")
                    try:
                        with zip_ref.open(filename) as f:
                            data = json.load(f)
                            print(f"{Fore.CYAN}Parsing {filename}...{Style.RESET_ALL}")
                            self._process_file(filename, data)
                            self._stats['processed_files'] += 1
                    except json.JSONDecodeError as e:
                        self.logger.error(f"Error parsing {filename}: {str(e)}")
                        self._stats['errors'] += 1
                        continue

            self._print_summary()
            return self._data
            
        except Exception as e:
            self.logger.error(f"Error parsing zip file: {str(e)}")
            raise

    def _process_file(self, filename: str, data: Dict):
        """Process individual BloodHound JSON files"""
        filename_lower = filename.lower()
        
        # Extract data array
        data_items = data.get('data', [])
        if not data_items:
            self._stats['skipped'] += 1
            return

        for item in data_items:
            self._process_item(item, filename_lower)

    def _process_item(self, item: Dict, filename: str):
        """Process individual items from BloodHound data"""
        # Get properties
        props = item.get('Properties', {})
        
        # Store items based on filename pattern
        if 'computers' in filename:
            self._data['computers'].append(item)
        elif 'users' in filename:
            self._data['users'].append(item)
        elif 'groups' in filename:
            self._data['groups'].append(item)
        elif 'domains' in filename:
            self._data['domains'].append(item)
        elif 'gpos' in filename:
            self._data['gpos'].append(item)
        elif 'ous' in filename:
            self._data['ous'].append(item)
        elif 'certtemplates' in filename:
            self._data['certificate_templates'].append(item)
        elif 'enterprisecas' in filename:
            self._data['enterprise_cas'].append(item)
        elif 'rootcas' in filename:
            self._data['root_cas'].append(item)
        elif 'aiacas' in filename:
            self._data['aia_cas'].append(item)
        elif 'ntauthstores' in filename:
            self._data['ntauth_store'].append(item)
        elif 'containers' in filename:
            self._data['containers'].append(item)

        # Process relationships
        self._process_item_relationships(item)

    def _process_item_relationships(self, item: Dict):
        """Process relationships from an item"""
        # Process ACEs
        if 'Aces' in item:
            for ace in item['Aces']:
                if all(k in ace for k in ['PrincipalSID', 'RightName']):
                    obj_id = item.get('Properties', {}).get('objectid')
                    if obj_id:
                        self._data['relationships'].append({
                            'StartNode': ace['PrincipalSID'],
                            'EndNode': obj_id,
                            'RelationshipType': ace['RightName'],
                            'Properties': {
                                'IsInherited': ace.get('IsInherited', False),
                                'PrincipalType': ace.get('PrincipalType')
                            }
                        })

        # Process Members
        if 'Members' in item:
            obj_id = item.get('Properties', {}).get('objectid')
            if obj_id:
                for member in item['Members']:
                    if 'ObjectIdentifier' in member:
                        self._data['relationships'].append({
                            'StartNode': member['ObjectIdentifier'],
                            'EndNode': obj_id,
                            'RelationshipType': 'MemberOf',
                            'Properties': {
                                'ObjectType': member.get('ObjectType')
                            }
                        })

        # Process GPO Links
        if 'GPOLinks' in item:
            obj_id = item.get('Properties', {}).get('objectid')
            if obj_id:
                for link in item['GPOLinks']:
                    if 'GUID' in link:
                        self._data['relationships'].append({
                            'StartNode': obj_id,
                            'EndNode': link['GUID'],
                            'RelationshipType': 'GPLink',
                            'Properties': {
                                'Enforced': link.get('IsEnforced', False)
                            }
                        })

    def _print_summary(self):
        """Print summary of parsed data"""
        print(f"\n{Fore.GREEN}Parsing Summary:{Style.RESET_ALL}")
        print(f"  → Files Processed: {self._stats['processed_files']}")
        print(f"  → Errors: {self._stats['errors']}")
        print(f"  → Skipped: {self._stats['skipped']}")
        
        # Print object counts
        for key, value in {
            'Computers': len(self._data['computers']),
            'Users': len(self._data['users']),
            'Groups': len(self._data['groups']),
            'Domains': len(self._data['domains']),
            'Relationships': len(self._data['relationships']),
            'Certificate Templates': len(self._data['certificate_templates']),
            'Enterprise CAs': len(self._data['enterprise_cas'])
        }.items():
            print(f"  → {key}: {value}")

    def get_statistics(self) -> Dict[str, Any]:
        """Get processing statistics"""
        return {
            'stats': self._stats,
            'counts': {
                'computers': len(self._data['computers']),
                'users': len(self._data['users']),
                'groups': len(self._data['groups']),
                'domains': len(self._data['domains']),
                'relationships': len(self._data['relationships'])
            }
        }

    def get_data(self) -> Dict[str, Any]:
        """Get the processed data"""
        return self._data
    
    def analyze_data(self) -> Dict[str, Any]:
        """Analyze parsed BloodHound data"""
        print(f"\n{Fore.CYAN}Analyzing data...{Style.RESET_ALL}")
        
        analysis = {
            'summary': {
                'computers': len(self._data['computers']),
                'users': len(self._data['users']),
                'groups': len(self._data['groups']),
                'domains': len(self._data['domains']),
                'relationships': len(self._data['relationships']),
                'certificate_templates': len(self._data['certificate_templates']),
                'enterprise_cas': len(self._data['enterprise_cas'])
            },
            'security_findings': self._analyze_security_issues(),
            'privileged_accounts': self._analyze_privileged_accounts(),
            'vulnerable_systems': self._analyze_vulnerable_systems(),
            'certificate_analysis': self._analyze_certificates()
        }

        self._print_analysis(analysis)
        return analysis

    def _get_property(self, obj: Dict, prop: str, default: Any = None) -> Any:
        """Safely get a property from an object"""
        try:
            return obj.get('Properties', {}).get(prop, default)
        except (AttributeError, KeyError):
            return default

    def _analyze_security_issues(self) -> List[Dict]:
        """Analyze security issues from the data"""
        findings = []
        
        # Check for computers without LAPS
        computers_without_laps = []
        for computer in self._data['computers']:
            if not self._get_property(computer, 'haslaps', False):
                name = self._get_property(computer, 'name')
                if name:
                    computers_without_laps.append(name)
        
        if computers_without_laps:
            findings.append({
                'issue': 'Computers without LAPS',
                'severity': 'HIGH',
                'count': len(computers_without_laps),
                'affected': computers_without_laps
            })

        # Check for users with password not required
        users_no_pass = []
        for user in self._data['users']:
            if self._get_property(user, 'passwordnotreqd', False):
                name = self._get_property(user, 'name')
                if name:
                    users_no_pass.append(name)
        
        if users_no_pass:
            findings.append({
                'issue': 'Users with Password Not Required',
                'severity': 'HIGH',
                'count': len(users_no_pass),
                'affected': users_no_pass
            })

        return findings

    def _analyze_privileged_accounts(self) -> Dict[str, List[str]]:
        """Analyze privileged accounts"""
        privileged = {
            'domain_admins': [],
            'enterprise_admins': [],
            'administrators': []
        }
        
        for group in self._data['groups']:
            sid = self._get_property(group, 'objectid', '')
            name = str(self._get_property(group, 'name', '')).lower()
            
            if not sid:
                continue
                
            if sid.endswith('-512') or 'domain admins' in name:
                privileged['domain_admins'].extend(
                    self._get_group_members(group)
                )
            elif sid.endswith('-519') or 'enterprise admins' in name:
                privileged['enterprise_admins'].extend(
                    self._get_group_members(group)
                )
            elif sid.endswith('-544') or 'administrators' in name:
                privileged['administrators'].extend(
                    self._get_group_members(group)
                )

        return {k: list(set(v)) for k, v in privileged.items()}  # Remove duplicates

    def _analyze_vulnerable_systems(self) -> List[Dict]:
        """Analyze vulnerable systems"""
        vulnerable = []
        
        # Check for outdated operating systems
        outdated_os_pattern = r'.*(2000|2003|2008|xp|vista|7|8|2012).*'
        
        for computer in self._data['computers']:
            os = str(self._get_property(computer, 'operatingsystem', '')).lower()
            if re.match(outdated_os_pattern, os):
                name = self._get_property(computer, 'name')
                if name:
                    vulnerable.append({
                        'name': name,
                        'os': os,
                        'enabled': self._get_property(computer, 'enabled', False)
                    })
                
        return vulnerable

    def _analyze_certificates(self) -> Dict[str, Any]:
        """Analyze certificate-related vulnerabilities"""
        analysis = {
            'vulnerable_templates': [],
            'misconfigured_cas': []
        }

        # Check certificate templates
        for template in self._data['certificate_templates']:
            props = template.get('Properties', {})
            vulns = []
            
            # ESC1: Client Authentication + User Supplied SAN
            if (props.get('Client Authentication', False) and 
                props.get('Enrollee Supplies Subject', True)):
                vulns.append('ESC1')
            
            # ESC2: Any Purpose EKU
            ekus = props.get('Extended Key Usage', [])
            if not ekus or 'Any Purpose' in ekus:
                vulns.append('ESC2')
                
            # ESC3: Certificate Request Agent
            if ekus and 'Certificate Request Agent' in ekus:
                vulns.append('ESC3')

            if vulns:
                name = self._get_property(template, 'name')
                if name:
                    analysis['vulnerable_templates'].append({
                        'name': name,
                        'vulnerabilities': vulns
                    })

        return analysis

    def _get_group_members(self, group: Dict) -> List[str]:
        """Get members of a group"""
        members = set()
        
        # Get direct members from Members array
        for member in group.get('Members', []):
            member_id = member.get('ObjectIdentifier')
            if member_id:
                members.add(member_id)
        
        # Get members from relationships
        group_id = self._get_property(group, 'objectid')
        if group_id:
            for rel in self._data['relationships']:
                if (rel.get('EndNode') == group_id and 
                    rel.get('RelationshipType') == 'MemberOf'):
                    start_node = rel.get('StartNode')
                    if start_node:
                        members.add(start_node)
                
        return list(members)

    def _get_user_name(self, user_id: str) -> str:
        """Get user name from user ID"""
        for user in self._data['users']:
            if self._get_property(user, 'objectid') == user_id:
                return self._get_property(user, 'name', '')
        return ''

    def _print_analysis(self, analysis: Dict):
        """Print analysis findings"""
        print(f"\n{Fore.GREEN}Analysis Results:{Style.RESET_ALL}")
        
        # Print security findings
        if analysis['security_findings']:
            print(f"\n{Fore.RED}Security Issues:{Style.RESET_ALL}")
            for finding in analysis['security_findings']:
                print(f"  → {finding['issue']}: {finding['count']} affected")
                if self.debug:
                    for affected in finding['affected'][:5]:
                        print(f"    - {affected}")
                    if len(finding['affected']) > 5:
                        print(f"    - ... and {len(finding['affected']) - 5} more")
                
        # Print privileged accounts
        print(f"\n{Fore.YELLOW}Privileged Accounts:{Style.RESET_ALL}")
        for group, members in analysis['privileged_accounts'].items():
            print(f"  → {group.replace('_', ' ').title()}: {len(members)} members")
            if self.debug and members:
                resolved_names = [self._get_user_name(m) for m in members]
                for name in resolved_names[:5]:
                    if name:
                        print(f"    - {name}")
                if len(resolved_names) > 5:
                    print(f"    - ... and {len(resolved_names) - 5} more")
            
        # Print vulnerable systems
        if analysis['vulnerable_systems']:
            print(f"\n{Fore.RED}Vulnerable Systems:{Style.RESET_ALL}")
            print(f"  → Found {len(analysis['vulnerable_systems'])} systems with outdated OS")
            if self.debug:
                for system in analysis['vulnerable_systems'][:5]:
                    print(f"    - {system['name']} ({system['os']})")
                if len(analysis['vulnerable_systems']) > 5:
                    print(f"    - ... and {len(analysis['vulnerable_systems']) - 5} more")

        # Print certificate findings
        cert_analysis = analysis['certificate_analysis']
        if cert_analysis['vulnerable_templates']:
            print(f"\n{Fore.RED}Certificate Vulnerabilities:{Style.RESET_ALL}")
            print(f"  → Found {len(cert_analysis['vulnerable_templates'])} vulnerable templates")
            if self.debug:
                for template in cert_analysis['vulnerable_templates'][:5]:
                    print(f"    - {template['name']}: {', '.join(template['vulnerabilities'])}")
                if len(cert_analysis['vulnerable_templates']) > 5:
                    print(f"    - ... and {len(cert_analysis['vulnerable_templates']) - 5} more")