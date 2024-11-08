from typing import Dict, List, Any
from datetime import datetime
import re

def format_timestamp(timestamp: float) -> str:
    """Convert epoch timestamp to readable format"""
    try:
        return datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
    except:
        return "Invalid Timestamp"

def format_path(path: Dict) -> str:
    """Format Neo4j path for readable output"""
    nodes = path.get('nodes', [])
    rels = path.get('relationships', [])
    
    if not nodes:
        return "Empty Path"
        
    path_str = nodes[0].get('name', 'Unknown')
    for i, rel in enumerate(rels):
        rel_type = rel.get('type', 'Unknown')
        next_node = nodes[i+1].get('name', 'Unknown')
        path_str += f" -{rel_type}-> {next_node}"
        
    return path_str

def sanitize_cypher(query: str) -> str:
    """Sanitize user input for Cypher queries"""
    # Remove any attempts at comment injection
    query = re.sub(r'/\*.*?\*/', '', query)
    # Remove any attempts at chaining queries
    query = query.split(';')[0]
    return query

def parse_bloodhound_output(output: Dict) -> Dict[str, Any]:
    """Parse BloodHound output into standardized format"""
    parsed = {
        'nodes': [],
        'relationships': [],
        'metadata': {
            'timestamp': datetime.now().isoformat(),
            'query_type': output.get('type', 'unknown')
        }
    }
    
    # Parse nodes
    for node in output.get('nodes', []):
        parsed['nodes'].append({
            'id': node.get('id'),
            'name': node.get('name'),
            'type': node.get('type'),
            'properties': node.get('properties', {})
        })
        
    # Parse relationships
    for rel in output.get('relationships', []):
        parsed['relationships'].append({
            'source': rel.get('source'),
            'target': rel.get('target'),
            'type': rel.get('type'),
            'properties': rel.get('properties', {})
        })
        
    return parsed
