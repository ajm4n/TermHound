from typing import Dict, List, Any
from colorama import init, Fore, Back, Style
from datetime import datetime
import json

# Initialize colorama for cross-platform colored output
init()

class TerminalReporter:
    """Terminal-based report generator with color coding"""
    
    SEVERITY_COLORS = {
        "CRITICAL": Fore.RED + Style.BRIGHT,
        "HIGH": Fore.RED,
        "MEDIUM": Fore.YELLOW,
        "LOW": Fore.BLUE,
        "INFO": Fore.WHITE
    }

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

    def print_finding(self, title: str, details: List[str], severity: str = "HIGH"):
        color = self.SEVERITY_COLORS.get(severity, Fore.WHITE)
        print(f"\n{color}[!] {title}{Style.RESET_ALL}")
        for detail in details:
            print(f"{color}    → {detail}{Style.RESET_ALL}")

    def print_attack_path(self, path: str, path_type: str = "Attack Path"):
        print(f"{Fore.RED}[>] {path_type}: {path}{Style.RESET_ALL}")

    def generate_report(self, report_data: Dict[str, Any]):
        """Generate formatted terminal report"""
        self.print_banner()
        print(f"Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

        # Domain Security Analysis
        if 'domain_security' in report_data:
            self.print_section("Domain Security Analysis")
            domain_data = report_data['domain_security']
            
            for vuln in domain_data.get('vulnerabilities', []):
                self.print_finding(
                    vuln['title'],
                    vuln['details'],
                    vuln.get('severity', 'MEDIUM')
                )

        # Certificate Security Analysis
        if 'certificate_security' in report_data:
            self.print_section("Certificate Security Analysis")
            cert_data = report_data['certificate_security']
            
            for esc in cert_data.get('esc_findings', []):
                self.print_finding(
                    f"ESC{esc['id']}: {esc['title']}",
                    esc['affected_templates'],
                    "CRITICAL"
                )

        # Kerberos Security Analysis
        if 'kerberos_security' in report_data:
            self.print_section("Kerberos Security Analysis")
            kerb_data = report_data['kerberos_security']
            
            if kerb_data.get('as_rep'):
                self.print_finding(
                    "AS-REP Roasting Possible",
                    [f"Account: {acc}" for acc in kerb_data['as_rep']],
                    "HIGH"
                )

        # Attack Path Analysis
        if 'attack_paths' in report_data:
            self.print_section("Attack Path Analysis")
            paths = report_data['attack_paths']
            
            if paths.get('domain_admin'):
                for path in paths['domain_admin']:
                    self.print_attack_path(path, "Path to Domain Admin")
            
            if paths.get('owned_paths'):
                for path in paths['owned_paths']:
                    self.print_attack_path(path, "Path from Owned User")

class JSONReporter:
    """JSON report generator"""
    
    def generate_report(self, report_data: Dict[str, Any], output_file: str):
        """Generate JSON report file"""
        try:
            with open(output_file, 'w') as f:
                json.dump(
                    report_data,
                    f,
                    indent=2,
                    default=str,
                    sort_keys=True
                )
        except Exception as e:
            print(f"{Fore.RED}Error generating JSON report: {str(e)}{Style.RESET_ALL}")
            raise
