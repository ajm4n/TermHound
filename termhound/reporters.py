from typing import Dict, List, Any
from colorama import init, Fore, Back, Style
from datetime import datetime
import json

init()

class VulnerabilityDescriptions:
    """Detailed vulnerability descriptions with context"""
    
    DOMAIN = {
        'LAPS_Missing': {
            'severity': 'HIGH',
            'description': 'Local Administrator Password Solution (LAPS) is not implemented.',
            'attack_details': 'Without LAPS, local admin passwords are often reused across systems. If an attacker compromises one local admin password, they can attempt to use it on other systems.',
            'impact': 'Lateral movement, privilege escalation, and potential domain compromise',
            'mitigation': 'Deploy LAPS to automatically manage and rotate local administrator passwords.',
            'detection': 'Monitor for local administrator password age and usage patterns.'
        },
        'Password_Not_Required': {
            'severity': 'CRITICAL',
            'description': 'Accounts are configured to allow empty passwords.',
            'attack_details': 'Accounts can be accessed without any password, allowing unauthorized access.',
            'impact': 'Immediate unauthorized access to affected accounts',
            'mitigation': 'Enable "Password required" for all accounts and implement strong password policies.',
            'detection': 'Regular security audits of account settings.'
        },
        'Password_Never_Expires': {
            'severity': 'MEDIUM',
            'description': 'Accounts have passwords set to never expire.',
            'attack_details': 'Old passwords are more likely to be compromised through various attack methods.',
            'impact': 'Increased risk of password compromise and account takeover',
            'mitigation': 'Implement password expiration policies with regular rotation.',
            'detection': 'Monitor password age and changes.'
        },
        'Disabled_Admin_Account': {
            'severity': 'MEDIUM',
            'description': 'Disabled accounts with administrative privileges exist.',
            'attack_details': 'Attackers can re-enable accounts if they gain sufficient privileges.',
            'impact': 'Potential privilege escalation if account is re-enabled',
            'mitigation': 'Remove administrative privileges before disabling accounts.',
            'detection': 'Monitor for account status changes.'
        },
        'AdminTo_Rights': {
            'severity': 'HIGH',
            'description': 'Non-administrative users have admin rights on systems.',
            'attack_details': 'Users can perform administrative actions on systems they shouldnt have access to.',
            'impact': 'Unauthorized system access and potential privilege escalation',
            'mitigation': 'Review and remove unnecessary admin rights.',
            'detection': 'Audit admin group memberships regularly.'
        }
    }

    KERBEROS = {
        'AS-REP Roasting': {
            'severity': 'HIGH',
            'description': 'Accounts with "Do not require Kerberos preauthentication" enabled.',
            'attack_details': 'AS-REP roasting attack possible against these accounts.',
            'impact': 'Password cracking and account compromise possible',
            'mitigation': 'Enable Kerberos preauthentication for all accounts.',
            'detection': 'Monitor for abnormal Kerberos TGT requests.'
        },
        'Kerberoasting': {
            'severity': 'HIGH',
            'description': 'Service accounts with SPNs vulnerable to Kerberoasting.',
            'attack_details': 'Service tickets can be requested and cracked offline.',
            'impact': 'Service account compromise and privilege escalation',
            'mitigation': 'Use strong service account passwords, implement AES.',
            'detection': 'Monitor for unusual service ticket requests.'
        },
        'Unconstrained_Delegation': {
            'severity': 'CRITICAL',
            'description': 'Systems with unconstrained delegation enabled.',
            'attack_details': 'Can impersonate any user connecting to these systems.',
            'impact': 'Complete domain compromise possible',
            'mitigation': 'Use constrained delegation where necessary.',
            'detection': 'Audit delegation settings regularly.'
        }
    }

    CERTIFICATES = {
        'ESC1': {
            'severity': 'CRITICAL',
            'description': 'Certificate template vulnerable to ESC1 (Client Authentication + Subject Alternative Name).',
            'attack_details': 'Attacker can specify any user in certificate request.',
            'impact': 'Domain privilege escalation and user impersonation',
            'mitigation': 'Disable subject alternative name flag.',
            'detection': 'Monitor certificate requests for unusual SANs.'
        },
        'ESC2': {
            'severity': 'CRITICAL',
            'description': 'Certificate template has weak EKU configuration.',
            'attack_details': 'Certificates can be used for any purpose.',
            'impact': 'Multiple attack vectors possible',
            'mitigation': 'Configure specific EKU requirements.',
            'detection': 'Audit certificate template configurations.'
        },
        'ESC3': {
            'severity': 'HIGH',
            'description': 'Enrollment agent templates available.',
            'attack_details': 'Can request certificates on behalf of other users.',
            'impact': 'Certificate request abuse',
            'mitigation': 'Restrict enrollment agent templates.',
            'detection': 'Monitor enrollment agent certificate usage.'
        }
    }

    ATTACK_PATHS = {
        'DA_Path': {
            'severity': 'CRITICAL',
            'description': 'Path to Domain Admin exists.',
            'attack_details': 'Attack path available to reach Domain Admin privileges.',
            'impact': 'Complete domain compromise possible',
            'mitigation': 'Break attack paths through privilege removal.',
            'detection': 'Regular attack path analysis.'
        },
        'High_Value_Path': {
            'severity': 'HIGH',
            'description': 'Path to high-value target exists.',
            'attack_details': 'Chain of permissions leads to sensitive target.',
            'impact': 'Privilege escalation possible',
            'mitigation': 'Implement tiered admin model.',
            'detection': 'Monitor privilege changes in path.'
        },
        'Owned_Path': {
            'severity': 'CRITICAL',
            'description': 'Attack path from owned asset exists.',
            'attack_details': 'Compromised asset can reach sensitive targets.',
            'impact': 'Lateral movement and escalation possible',
            'mitigation': 'Isolate compromised assets.',
            'detection': 'Monitor for lateral movement attempts.'
        }
    }

class TerminalReporter:
    def __init__(self):
        self.vuln_desc = VulnerabilityDescriptions()

    def print_banner(self):
        banner = f"""
{Fore.CYAN}{Style.BRIGHT}
╔════════════════════════════════════════════════════════════════╗
║                                                                ║
║  TermHound - Active Directory Security Analysis                ║
║                                                                ║
╚════════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}"""
        print(banner)

    def print_section(self, title: str):
        print(f"\n{Fore.CYAN}{Style.BRIGHT}{'='*80}")
        print(f" {title}")
        print(f"{'='*80}{Style.RESET_ALL}")

    def print_detailed_finding(self, vuln_type: str, details: Dict, context: Dict, severity: str = "HIGH"):
        color = {
            "CRITICAL": Fore.RED + Style.BRIGHT,
            "HIGH": Fore.RED,
            "MEDIUM": Fore.YELLOW,
            "LOW": Fore.BLUE
        }.get(severity, Fore.WHITE)
        
        print(f"\n{color}{'='*80}")
        print(f"VULNERABILITY: {vuln_type}")
        print(f"Severity: {severity}")
        print(f"{'='*80}{Style.RESET_ALL}")
        
        if description := details.get('description'):
            print(f"\n{Fore.WHITE}Description:{Style.RESET_ALL}")
            print(f"  {description}")
        
        if attack_details := details.get('attack_details'):
            print(f"\n{Fore.WHITE}Attack Details:{Style.RESET_ALL}")
            print(f"  {attack_details}")

        if affected := context.get('affected', []):
            print(f"\n{color}Affected Assets:{Style.RESET_ALL}")
            for asset in affected:
                print(f"\n  Asset: {asset.get('name', 'Unknown')}")
                if asset_type := asset.get('type'):
                    print(f"  Type: {asset_type}")
                if props := asset.get('properties', {}):
                    print("  Properties:")
                    for key, value in props.items():
                        print(f"    - {key}: {value}")
                if privs := asset.get('privileges', []):
                    print("  Associated Privileges:")
                    for priv in privs:
                        print(f"    - {priv}")
                if paths := asset.get('attack_paths', []):
                    print("  Attack Paths:")
                    for path in paths:
                        print(f"    → {' -> '.join(path)}")

        if impact := details.get('impact'):
            print(f"\n{Fore.RED}Impact:{Style.RESET_ALL}")
            print(f"  {impact}")

        if mitigation := details.get('mitigation'):
            print(f"\n{Fore.GREEN}Mitigation:{Style.RESET_ALL}")
            print(f"  {mitigation}")

        if detection := details.get('detection'):
            print(f"\n{Fore.YELLOW}Detection:{Style.RESET_ALL}")
            print(f"  {detection}")

    def generate_report(self, report_data: Dict[str, Any]):
        self.print_banner()
        print(f"Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

        self.print_section("Domain Security Analysis")
        if domain_data := report_data.get('domain_security'):
            self._report_domain_security(domain_data)

        self.print_section("Certificate Security Analysis")
        if cert_data := report_data.get('certificate_security'):
            self._report_certificate_security(cert_data)

        self.print_section("Kerberos Security Analysis")
        if kerb_data := report_data.get('kerberos_security'):
            self._report_kerberos_security(kerb_data)

        self.print_section("Attack Path Analysis")
        if path_data := report_data.get('attack_paths'):
            self._report_attack_paths(path_data)

    def _report_domain_security(self, domain_data: Dict):
        """Report domain security findings"""
        if 'info' in domain_data:
            info = domain_data['info']
            if 'computers_without_laps' in info:
                self.print_detailed_finding(
                    "Missing LAPS",
                    self.vuln_desc.DOMAIN['LAPS_Missing'],
                    {'affected': [{'name': comp, 'type': 'Computer'} for comp in info['computers_without_laps']]},
                    "HIGH"
                )

        if 'vulnerabilities' in domain_data:
            for vuln in domain_data['vulnerabilities']:
                vuln_type = vuln.get('issue', 'Unknown').replace(' ', '_')
                if vuln_type in self.vuln_desc.DOMAIN:
                    self.print_detailed_finding(
                        vuln.get('issue', vuln_type),
                        self.vuln_desc.DOMAIN[vuln_type],
                        {'affected': [{'name': name, 'type': 'Account'} for name in vuln.get('affected', [])]},
                        vuln.get('severity', 'MEDIUM')
                    )

    def _report_certificate_security(self, cert_data: Dict):
        """Report certificate security findings"""
        if 'templates' in cert_data:
            for template in cert_data['templates']:
                if vulns := template.get('vulnerabilities', []):
                    for vuln in vulns:
                        if vuln in self.vuln_desc.CERTIFICATES:
                            self.print_detailed_finding(
                                f"Certificate Template Vulnerability ({vuln})",
                                self.vuln_desc.CERTIFICATES[vuln],
                                {'affected': [{'name': template['name'], 'type': 'Certificate Template',
                                             'properties': template.get('properties', {})}]},
                                "CRITICAL"
                            )

    def _report_kerberos_security(self, kerb_data: Dict):
        """Report Kerberos security findings"""
        if asrep := kerb_data.get('as_rep'):
            self.print_detailed_finding(
                "AS-REP Roasting Vulnerability",
                self.vuln_desc.KERBEROS['AS-REP Roasting'],
                {'affected': [{'name': user, 'type': 'User'} for user in asrep]},
                "HIGH"
            )

        if spn := kerb_data.get('spn'):
            self.print_detailed_finding(
                "Kerberoastable Users",
                self.vuln_desc.KERBEROS['Kerberoasting'],
                {'affected': [{'name': user, 'type': 'User'} for user in spn]},
                "HIGH"
            )

        if del_users := kerb_data.get('delegations'):
            self.print_detailed_finding(
                "Delegation Vulnerabilities",
                self.vuln_desc.KERBEROS['Unconstrained_Delegation'],
                {'affected': [{'name': user, 'type': 'User'} for user in del_users]},
                "CRITICAL"
            )

    def _report_attack_paths(self, path_data: Dict):
        """Report attack path findings"""
        if da_paths := path_data.get('domain_admin'):
            self.print_detailed_finding(
                "Critical Paths to Domain Admin",
                self.vuln_desc.ATTACK_PATHS['DA_Path'],
                {'affected': [self._format_path(path) for path in da_paths]},
                "CRITICAL"
            )

        if hvt_paths := path_data.get('high_value'):
            self.print_detailed_finding(
                "Paths to High Value Targets",
                self.vuln_desc.ATTACK_PATHS['High_Value_Path'],
                {'affected': [self._format_path(path) for path in hvt_paths]},
                "HIGH"
            )

        if owned_paths := path_data.get('owned_paths'):
            self.print_detailed_finding(
                "Attack Paths from Owned Objects",
                self.vuln_desc.ATTACK_PATHS['Owned_Path'],
                {'affected': [self._format_path(path) for path in owned_paths]},
                "CRITICAL"
            )

    def _format_path(self, path: Dict) -> Dict:
        """Format attack path for display"""
        return {
            'name': f"{path.get('start', 'Unknown')} → {path.get('end', 'Unknown')}",
            'type': 'Attack Path',
            'properties': {
                'start_node': path.get('start'),
                'end_node': path.get('end'),
                'relationship_type': path.get('type'),
                'path_length': len(path.get('nodes', [])),
            }
        }

class JSONReporter:
    def generate_report(self, report_data: Dict[str, Any], output_file: str):
        """Generate detailed JSON report file"""
        try:
            report_data['generated_at'] = datetime.now().isoformat()
            with open(output_file, 'w') as f:
                json.dump(report_data, f, indent=2, default=str)
        except Exception as e:
            print(f"{Fore.RED}Error generating JSON report: {str(e)}{Style.RESET_ALL}")
            raise