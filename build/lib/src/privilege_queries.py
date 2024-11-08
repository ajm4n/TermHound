from typing import Dict, List, Any
from neo4j import Driver

class PrivilegeQueries:
    """Privilege and attack path analysis queries"""
    
    def __init__(self, driver: Driver):
        self.driver = driver

    def find_paths_to_da(self) -> List[Dict]:
        """Find attack paths to Domain Admins"""
        query = """
            MATCH p = shortestPath((u:User)-[r:MemberOf|HasSession|AdminTo|
            AllExtendedRights|ForceChangePassword|GenericAll|GenericWrite|
            WriteDacl|WriteOwner|Owns|GenericAll|WriteDacl|WriteOwner|
            ExecuteDCOM|AllowedToDelegate|ReadLAPSPassword*1..]->(g:Group))
            WHERE g.name CONTAINS 'DOMAIN ADMINS'
            RETURN p
        """
        with self.driver.session() as session:
            return list(session.run(query))

    def find_paths_from_owned(self) -> List[Dict]:
        """Find attack paths from owned principals"""
        queries = {
            "to_da": """
                MATCH p = shortestPath((u:User)-[r:MemberOf|HasSession|AdminTo|
                AllExtendedRights|ForceChangePassword|GenericAll|GenericWrite|
                WriteDacl|WriteOwner*1..]->(g:Group))
                WHERE u.owned = true 
                AND g.name CONTAINS 'DOMAIN ADMINS'
                RETURN p
            """,
            "to_high_value": """
                MATCH p = shortestPath((u:User)-[r:MemberOf|HasSession|AdminTo|
                AllExtendedRights|ForceChangePassword|GenericAll|GenericWrite|
                WriteDacl|WriteOwner*1..]->(t))
                WHERE u.owned = true 
                AND t.highvalue = true
                RETURN p
            """
        }
        return self._execute_queries(queries)

    def find_paths_to_high_value(self) -> List[Dict]:
        """Find attack paths to high value targets"""
        query = """
            MATCH p = shortestPath((u:User)-[r:MemberOf|HasSession|AdminTo|
            AllExtendedRights|ForceChangePassword|GenericAll|GenericWrite|
            WriteDacl|WriteOwner*1..]->(t {highvalue: true}))
            RETURN p
        """
        with self.driver.session() as session:
            return list(session.run(query))

    def find_dangerous_privileges(self) -> Dict[str, List[Dict]]:
        """Find dangerous privilege configurations"""
        queries = {
            "dcsync_rights": """
                MATCH (n {highvalue:true})
                MATCH (m)-[:GetChanges*1..]->(n)
                WHERE NOT m.name CONTAINS 'DOMAIN CONTROLLERS'
                RETURN m.name, n.name
            """,
            "generic_all": """
                MATCH p=(m:Group)-[r:GenericAll]->(n)
                WHERE m.objectid ENDS WITH '-513'
                RETURN m.name, n.name
            """,
            "dangerous_delegates": """
                MATCH p=(u:User)-[r:AllowedToDelegate]->(c:Computer)
                WHERE u.enabled = true
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
