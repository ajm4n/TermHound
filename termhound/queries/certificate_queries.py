from typing import Dict, List, Any
from neo4j import Driver

class CertificateQueries:
    """Certificate template and authority analysis queries"""
    
    def __init__(self, driver: Driver):
        self.driver = driver

    def analyze_templates(self) -> List[Dict]:
        """Analyze certificate templates"""
        queries = {
            "all_templates": """
                MATCH (n:GPO) 
                WHERE n.type = 'Certificate Template' 
                RETURN n
            """,
            "enabled_templates": """
                MATCH (n:GPO) 
                WHERE n.type = 'Certificate Template' 
                AND n.Enabled = true 
                RETURN n
            """
        }
        return self._execute_queries(queries)

    def analyze_esc_vulnerabilities(self) -> List[Dict]:
        """Analyze ESC vulnerabilities"""
        queries = {
            "esc1": """
                MATCH (n:GPO) 
                WHERE n.type = 'Certificate Template' 
                AND n.`Enrollee Supplies Subject` = true 
                AND n.`Client Authentication` = true 
                AND n.`Enabled` = true  
                RETURN n
            """,
            "esc2": """
                MATCH (n:GPO) 
                WHERE n.type = 'Certificate Template' 
                AND n.`Enabled` = true 
                AND (n.`Extended Key Usage` = [] 
                OR 'Any Purpose' IN n.`Extended Key Usage` 
                OR n.`Any Purpose` = True) 
                RETURN n
            """,
            "esc3": """
                MATCH (n:GPO) 
                WHERE n.type = 'Certificate Template' 
                AND n.`Enabled` = true 
                AND (n.`Extended Key Usage` = [] 
                OR 'Certificate Request Agent' IN n.`Extended Key Usage`
                OR 'Any Purpose' IN n.`Extended Key Usage` 
                OR n.`Any Purpose` = True) 
                RETURN n
            """,
            "esc15": """
                MATCH (n:GPO)
                WHERE n.type = 'Certificate Template'
                AND n.`Enabled` = true
                AND n.schemaVersion = 1
                RETURN n
            """
        }
        return self._execute_queries(queries)

    def analyze_authorities(self) -> List[Dict]:
        """Analyze certificate authorities"""
        queries = {
            "cas": """
                MATCH (n:GPO) 
                WHERE n.type = 'Enrollment Service' 
                RETURN n
            """,
            "vulnerable_cas": """
                MATCH (n:GPO) 
                WHERE n.type = 'Enrollment Service' 
                AND n.`User Specified SAN` = 'Enabled' 
                RETURN n
            """
        }
        return self._execute_queries(queries)

    def _execute_queries(self, queries: Dict[str, str]) -> Dict[str, List[Dict]]:
        """Execute multiple queries and return results"""
        results = {}
        with self.driver.session() as session:
            for name, query in queries.items():
                results[name] = list(session.run(query))
        return results

    def get_vulnerabilities(self) -> List[Dict]:
        """Get comprehensive certificate vulnerability report"""
        templates = self.analyze_templates()
        authorities = self.analyze_authorities()
        esc_findings = self.analyze_esc_vulnerabilities()

        vulnerabilities = []
        
        # Process ESC findings
        for esc_num, findings in esc_findings.items():
            if findings:
                vulnerabilities.append({
                    "type": "ESC",
                    "id": esc_num.replace("esc", ""),
                    "affected_templates": [
                        finding["n"]["name"] for finding in findings
                    ],
                    "severity": "HIGH"
                })

        # Process vulnerable CAs
        if authorities.get("vulnerable_cas"):
            vulnerabilities.append({
                "type": "Certificate Authority",
                "description": "CAs allowing user-specified SANs",
                "affected_cas": [
                    ca["n"]["name"] for ca in authorities["vulnerable_cas"]
                ],
                "severity": "HIGH"
            })

        return vulnerabilities
