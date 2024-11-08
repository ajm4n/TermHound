import json
from typing import Dict, Any
from colorama import Fore, Style

def inspect_bloodhound_file(data: Dict[str, Any]) -> Dict[str, Any]:
    """Inspect BloodHound JSON file structure"""
    inspection = {
        'keys': list(data.keys()),
        'counts': {},
        'sample_items': {}
    }
    
    # Count items of each type
    for key in data.keys():
        if isinstance(data[key], list):
            inspection['counts'][key] = len(data[key])
            if data[key]:
                inspection['sample_items'][key] = data[key][0]

    return inspection

def print_data_summary(data: Dict[str, Any]):
    """Print summary of parsed data"""
    print(f"\n{Fore.CYAN}Data Structure Summary:{Style.RESET_ALL}")
    print(f"Root keys: {', '.join(data.keys())}")
    
    for key, count in data.get('counts', {}).items():
        print(f"\n{Fore.GREEN}{key}:{Style.RESET_ALL} {count} items")
        if key in data.get('sample_items', {}):
            sample = data['sample_items'][key]
            print("Sample item structure:")
            print(json.dumps(sample, indent=2)[:200] + "...")

def analyze_relationships(relationships: list):
    """Analyze relationship types in the data"""
    relationship_types = {}
    for rel in relationships:
        rel_type = rel.get('RelationshipType', 'Unknown')
        if rel_type not in relationship_types:
            relationship_types[rel_type] = 0
        relationship_types[rel_type] += 1
    
    print(f"\n{Fore.CYAN}Relationship Types:{Style.RESET_ALL}")
    for rel_type, count in relationship_types.items():
        print(f"  → {rel_type}: {count}")
