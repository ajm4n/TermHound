from typing import Dict, List, Any
from neo4j import Driver

class KerberosQueries:
    """Kerberos security analysis queries"""
    
    def __init__(self, driver: Driver):
        self.driver = driver

    def analyze_asrep_roasting(self) -> List[Dict]:
        """Find AS-REP roastable accounts"""
        query = """
            MATCH (d:Domain)-[r:Contains*1..]->(u {dontreqpreauth: true}) 
            RETURN u
        """
        with self.driver.session() as session:
            return list(session.run(query))

    def analyze_kerberoasting(self) -> List[Dict]:
        """Find Kerberoastable accounts"""
        queries = {
            "kerberoastable": """
                MATCH (d:Domain)-[r:Contains*1..]->(u {hasspn: true}) 
                RETURN u
            """,
            "kerberoastable_admins": """
                MATCH (admins)-[r1:MemberOf*0..]->(g1:Group) 
                WHERE g1.objectid =~ "(?i)S-1-5-.*-512" 
                WITH COLLECT(admins) AS filter 
                MATCH (d:Domain)-[r:Contains*1..]->(u {hasspn: true}) 
                WHERE u IN filter 
                RETURN u
            """
        }
        return self._execute_queries(queries)

    def analyze_delegations(self) -> Dict[str, List[Dict]]:
        """Analyze delegation configurations"""
        queries = {
            "unconstrained": """
                MATCH (dca)-[r:MemberOf*0..]->(g:Group) 
                WHERE g.objectid =~ "S-1-5-.*-516" 
                WITH COLLECT(dca) AS exclude 
                MATCH p = (d:Domain)-[r:Contains*1..]->(uc {unconstraineddelegation: true}) 
                WHERE (uc:User OR uc:Computer) AND NOT uc IN exclude 
                RETURN p
            """,
            "constrained": """
                MATCH p = (a)-[:AllowedToDelegate]->(c:Computer) 
                RETURN p
            """,
            "resource_based": """
                MATCH p=(m)-[r:AllowedToAct]->(n) 
                RETURN p
            """
        }
        return self._execute_queries(queries)

    def get_high_risk_accounts(self) -> List[Dict]:
        """Identify high-risk Kerberos-related accounts"""
        query = """
            MATCH (u:User)
            WHERE (u.hasspn = true AND u.enabled = true) OR
                  (u.dontreqpreauth = true AND u.enabled = true) OR
                  u.unconstraineddelegation = true
            RETURN u.name as username,
                   u.hasspn as kerberoastable,
                   u.dontreqpreauth as asreproastable,
                   u.unconstraineddelegation as unconstrained
        """
        with self.driver.session() as session:
            return list(session.run(query))

    def _execute_queries(self, queries: Dict[str, str]) -> Dict[str, List[Dict]]:
        """Execute multiple queries and return results"""
        results = {}
        with self.driver.session() as session:
            for name, query in queries.items():
                results[name] = list(session.run(query))
        return results
