from typing import Dict, List, Any
from neo4j import Driver

class DomainQueries:
    """Domain security analysis queries"""
    
    def __init__(self, driver: Driver):
        self.driver = driver

    def get_domain_info(self) -> Dict[str, Any]:
        """Get basic domain information"""
        queries = {
            "domains": """
                MATCH (d:Domain) RETURN d
            """,
            "domain_controllers": """
                MATCH (n:Group) 
                WHERE n.objectid ENDS WITH "-516" 
                WITH n
                MATCH p=(c:Computer)-[:MemberOf*1..]->(n) 
                RETURN p
            """,
            "computers_without_laps": """
                MATCH p = (d:Domain)-[r:Contains*1..]->(c:Computer {haslaps: false}) 
                RETURN p
            """
        }
        return self._execute_queries(queries)

    def get_sensitive_accounts(self) -> List[Dict]:
        """Find sensitive accounts by keyword analysis"""
        query = """
            UNWIND ['admin', 'password', 'sensitive', 'secret', 'pass', 
                   'key', 'azure', 'privileged'] AS word 
            MATCH (n) 
            WHERE (toLower(n.name) CONTAINS toLower(word)) OR 
                  (toLower(n.description) CONTAINS toLower(word)) 
            RETURN n
        """
        with self.driver.session() as session:
            return list(session.run(query))

    def mark_owned_users(self, usernames: List[str]) -> List[Dict]:
        """Mark specified users as owned"""
        query = """
            MATCH (u:User)
            WHERE u.name IN $usernames
            SET u.owned = true
            RETURN u.name as name, u.owned as owned
        """
        with self.driver.session() as session:
            return list(session.run(query, usernames=usernames))

    def get_critical_assets(self) -> List[Dict]:
        """Identify critical domain assets"""
        queries = {
            "high_value_targets": """
                MATCH p = (d:Domain)-[r:Contains*1..]->(h {highvalue: true}) 
                RETURN p
            """,
            "domain_admins": """
                MATCH p=(u:User)-[:MemberOf*1..]->(g:Group)
                WHERE g.objectid ENDS WITH "-512"
                RETURN p
            """,
            "enterprise_admins": """
                MATCH p=(u:User)-[:MemberOf*1..]->(g:Group)
                WHERE g.objectid ENDS WITH "-519"
                RETURN p
            """
        }
        return self._execute_queries(queries)

    def get_vulnerabilities(self) -> List[Dict]:
        """Get domain-wide vulnerabilities"""
        queries = {
            "password_not_required": """
                MATCH p = (d:Domain)-[r:Contains*1..]->(u:User {passwordnotreqd: true}) 
                RETURN p
            """,
            "password_never_expires": """
                MATCH p = (d:Domain)-[r:Contains*1..]->(u:User {pwdneverexpires: True}) 
                WHERE NOT u.name starts with 'KRBTGT' 
                RETURN u
            """,
            "disabled_accounts_admin": """
                MATCH p=(u:User {enabled: false})-[:AdminTo]->(c:Computer)
                RETURN p
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
