from typing import Dict, List, Any
from colorama import init, Fore, Back, Style
from datetime import datetime
import json
from neo4j.graph import Node, Relationship, Path

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

    def format_neo4j_value(self, value):
        """Format Neo4j values for display"""
        if isinstance(value, (Node, Relationship)):
            return dict(value)
        elif isinstance(value, Path):
            return [dict(node) for node in value.nodes]
        elif isinstance(value, list):
            return [self.format_neo4j_value(v) for v in value]
        elif isinstance(value, dict):
            return {k: self.format_neo4j_value(v) for k, v in value.items()}
        return value

    def process_domain_info(self, domain_data: Dict) -> List[str]:
        """Process domain information into displayable strings"""
        details = []
        try:
            for category, data in domain_data.items():
                if isinstance(data, list):
                    for item in data:
                        if hasattr(item, 'get'):  # Check if item is dict-like
                            details.append(f"{category}: {item.get('name', 'Unknown')}")
                elif isinstance(data, dict):
                    details.append(f"{category}: {data.get('name', 'Unknown')}")
        except Exception as e:
            details.append(f"Error processing domain data: {str(e)}")
        return details

    def generate_report(self, report_data: Dict[str, Any]):
        """Generate formatted terminal report"""
        self.print_banner()
        print(f"Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

        try:
            # Domain Security Analysis
            if 'domain_security' in report_data:
                self.print_section("Domain Security Analysis")
                domain_data = report_data['domain_security']
                
                # Process domain info
                if 'info' in domain_data:
                    formatted_info = self.process_domain_info(domain_data['info'])
                    self.print_finding("Domain Information", formatted_info, "INFO")

                # Process vulnerabilities
                if 'vulnerabilities' in domain_data:
                    for vuln in domain_data['vulnerabilities']:
                        formatted_vuln = self.format_neo4j_value(vuln)
                        if isinstance(formatted_vuln, dict):
                            self.print_finding(
                                formatted_vuln.get('title', 'Vulnerability Found'),
                                [str(formatted_vuln.get('details', 'No details'))],
                                formatted_vuln.get('severity', 'HIGH')
                            )

            # Certificate Security Analysis
            if 'certificate_security' in report_data:
                self.print_section("Certificate Security Analysis")
                cert_data = report_data['certificate_security']
                
                if 'templates' in cert_data:
                    template_details = []
                    for template in cert_data['templates']:
                        formatted_template = self.format_neo4j_value(template)
                        if isinstance(formatted_template, dict):
                            template_details.append(
                                f"Template: {formatted_template.get('name', 'Unknown')}"
                            )
                    if template_details:
                        self.print_finding("Certificate Templates", template_details, "INFO")

            # Kerberos Security Analysis
            if 'kerberos_security' in report_data:
                self.print_section("Kerberos Security Analysis")
                kerb_data = report_data['kerberos_security']
                
                if 'as_rep' in kerb_data:
                    as_rep_details = []
                    for account in kerb_data['as_rep']:
                        formatted_account = self.format_neo4j_value(account)
                        if isinstance(formatted_account, dict):
                            as_rep_details.append(
                                f"Account: {formatted_account.get('name', 'Unknown')}"
                            )
                    if as_rep_details:
                        self.print_finding(
                            "AS-REP Roasting Possible", 
                            as_rep_details,
                            "HIGH"
                        )

        except Exception as e:
            print(f"{Fore.RED}Error during analysis: {str(e)}{Style.RESET_ALL}")

class JSONReporter:
    """JSON report generator"""
    
    def format_neo4j_value(self, value):
        """Format Neo4j values for JSON serialization"""
        if isinstance(value, (Node, Relationship)):
            return dict(value)
        elif isinstance(value, Path):
            return [dict(node) for node in value.nodes]
        elif isinstance(value, list):
            return [self.format_neo4j_value(v) for v in value]
        elif isinstance(value, dict):
            return {k: self.format_neo4j_value(v) for k, v in value.items()}
        return value

    def generate_report(self, report_data: Dict[str, Any], output_file: str):
        """Generate JSON report file"""
        try:
            # Format all Neo4j values for JSON serialization
            formatted_data = self.format_neo4j_value(report_data)
            
            with open(output_file, 'w') as f:
                json.dump(
                    formatted_data,
                    f,
                    indent=2,
                    default=str,
                    sort_keys=True
                )
        except Exception as e:
            print(f"{Fore.RED}Error generating JSON report: {str(e)}{Style.RESET_ALL}")
            raise
