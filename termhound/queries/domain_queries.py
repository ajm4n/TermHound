from typing import Dict, List, Any
from neo4j import Driver

class DomainQueries:
    def __init__(self, driver: Driver):
        self.driver = driver

    def get_domain_info(self) -> Dict[str, Any]:
        """Get summarized domain information"""
        queries = {
            "domains": """
                MATCH (d:Domain) 
                RETURN {
                    count: count(d),
                    names: collect(d.name)
                } as result
            """,
            "domain_controllers": """
                MATCH (n:Group) 
                WHERE n.objectid ENDS WITH "-516" 
                WITH n
                MATCH (c:Computer)-[:MemberOf*1..]->(n) 
                RETURN {
                    count: count(c),
                    names: collect(c.name)
                } as result
            """,
            "computers_without_laps": """
                MATCH (c:Computer {haslaps: false}) 
                RETURN {
                    count: count(c),
                    names: collect(c.name)
                } as result
            """
        }
        
        results = {}
        with self.driver.session() as session:
            for name, query in queries.items():
                result = session.run(query).single()
                if result:
                    results[name] = result['result']
                else:
                    results[name] = {'count': 0, 'names': []}
        return results

    def get_privileged_accounts(self) -> Dict[str, Any]:
        """Get information about privileged accounts"""
        queries = {
            "domain_admins": """
                MATCH (u:User)-[:MemberOf*1..]->(g:Group)
                WHERE g.objectid ENDS WITH "-512"
                RETURN {
                    count: count(DISTINCT u),
                    users: collect(DISTINCT {
                        name: u.name,
                        enabled: u.enabled,
                        lastlogon: u.lastlogon
                    })
                } as result
            """,
            "enterprise_admins": """
                MATCH (u:User)-[:MemberOf*1..]->(g:Group)
                WHERE g.objectid ENDS WITH "-519"
                RETURN {
                    count: count(DISTINCT u),
                    users: collect(DISTINCT {
                        name: u.name,
                        enabled: u.enabled,
                        lastlogon: u.lastlogon
                    })
                } as result
            """,
            "administrators": """
                MATCH (u:User)-[:MemberOf*1..]->(g:Group)
                WHERE g.objectid ENDS WITH "-544"
                RETURN {
                    count: count(DISTINCT u),
                    users: collect(DISTINCT {
                        name: u.name,
                        enabled: u.enabled,
                        lastlogon: u.lastlogon
                    })
                } as result
            """,
            "backup_operators": """
                MATCH (u:User)-[:MemberOf*1..]->(g:Group)
                WHERE g.objectid ENDS WITH "-551"
                RETURN {
                    count: count(DISTINCT u),
                    users: collect(DISTINCT {
                        name: u.name,
                        enabled: u.enabled,
                        lastlogon: u.lastlogon
                    })
                } as result
            """,
            "account_operators": """
                MATCH (u:User)-[:MemberOf*1..]->(g:Group)
                WHERE g.objectid ENDS WITH "-548"
                RETURN {
                    count: count(DISTINCT u),
                    users: collect(DISTINCT {
                        name: u.name,
                        enabled: u.enabled,
                        lastlogon: u.lastlogon
                    })
                } as result
            """,
            "local_admin_rights": """
                MATCH (u:User)-[r:AdminTo]->(c:Computer)
                WITH u, count(c) as computer_count, collect(c.name) as computers
                RETURN {
                    count: count(u),
                    users: collect({
                        name: u.name,
                        computer_count: computer_count,
                        computers: computers
                    })
                } as result
            """
        }
        
        results = {}
        with self.driver.session() as session:
            for name, query in queries.items():
                result = session.run(query).single()
                if result:
                    results[name] = result['result']
                else:
                    results[name] = {'count': 0, 'users': []}
        return results

    def get_vulnerabilities(self) -> List[Dict]:
        """Get domain-wide vulnerabilities in summarized format"""
        queries = {
            "password_not_required": """
                MATCH (u:User {passwordnotreqd: true}) 
                RETURN {
                    title: 'Users with Password Not Required',
                    count: count(u),
                    details: collect(u.name)
                } as result
            """,
            "password_never_expires": """
                MATCH (u:User {pwdneverexpires: true})
                WHERE NOT u.name STARTS WITH 'KRBTGT'
                RETURN {
                    title: 'Users with Password Never Expires',
                    count: count(u),
                    details: collect(u.name)
                } as result
            """,
            "disabled_admin_accounts": """
                MATCH (u:User {enabled: false})-[:AdminTo]->(c:Computer)
                RETURN {
                    title: 'Disabled Users with Admin Rights',
                    count: count(DISTINCT u),
                    details: collect(DISTINCT u.name)
                } as result
            """
        }
        
        results = []
        with self.driver.session() as session:
            for name, query in queries.items():
                result = session.run(query).single()
                if result and result['result']['count'] > 0:
                    results.append(result['result'])
        return results

    def get_critical_assets(self) -> Dict[str, Any]:
        """Get summarized critical asset information"""
        queries = {
            "high_value_targets": """
                MATCH (h {highvalue: true})
                RETURN {
                    count: count(h),
                    details: collect({name: h.name, type: labels(h)[0]})
                } as result
            """,
            "domain_admins": """
                MATCH (u:User)-[:MemberOf*1..]->(g:Group)
                WHERE g.objectid ENDS WITH "-512"
                RETURN {
                    count: count(DISTINCT u),
                    names: collect(DISTINCT u.name)
                } as result
            """
        }
        
        results = {}
        with self.driver.session() as session:
            for name, query in queries.items():
                result = session.run(query).single()
                if result:
                    results[name] = result['result']
        return results

    def format_neo4j_results(self, value: Any) -> str:
        """Format Neo4j results for display"""
        if isinstance(value, (list, set)):
            return list(value)
        if isinstance(value, dict):
            return {k: self.format_neo4j_results(v) for k, v in value.items()}
        return str(value)
