import argparse
import sys
from typing import Dict, List, Optional
from termhound.analyzer import TermHoundAnalyzer
from colorama import init, Fore, Style

init()

def main():
    parser = argparse.ArgumentParser(description='TermHound - AD Security Analysis Tool')
    
    # Add source type argument
    parser.add_argument('--source', choices=['neo4j', 'bloodhound'], required=True,
                      help='Data source type (neo4j or bloodhound)')

    # Source-specific arguments
    neo4j_group = parser.add_argument_group('Neo4j options')
    neo4j_group.add_argument('--uri', help='Neo4j database URI')
    neo4j_group.add_argument('--username', help='Neo4j username')
    neo4j_group.add_argument('--password', help='Neo4j password')
    
    bloodhound_group = parser.add_argument_group('BloodHound options')
    bloodhound_group.add_argument('--zip', help='Path to BloodHound zip file')
    
    # Common arguments
    parser.add_argument('--output', required=True, help='Output report file')
    parser.add_argument('--owned', nargs='+', help='List of owned usernames')
    parser.add_argument('--debug', action='store_true', help='Enable debug output')
    
    args = parser.parse_args()
    
    try:
        if args.source == 'neo4j':
            if not all([args.uri, args.username, args.password]):
                print(f"{Fore.RED}Error: Neo4j source requires --uri, --username, and --password{Style.RESET_ALL}")
                sys.exit(1)
            analyzer = TermHoundAnalyzer(
                source_type='neo4j',
                uri=args.uri,
                username=args.username,
                password=args.password,
                owned_users=args.owned
            )
        else:  # bloodhound
            if not args.zip:
                print(f"{Fore.RED}Error: BloodHound source requires --zip{Style.RESET_ALL}")
                sys.exit(1)
            analyzer = TermHoundAnalyzer(
                source_type='bloodhound',
                zip_path=args.zip,
                owned_users=args.owned,
                debug=args.debug
            )

        results = analyzer.analyze()
        
        # Save JSON report
        import json
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2, default=str)
            
        print(f"\n{Fore.GREEN}Analysis complete! Report saved to: {args.output}{Style.RESET_ALL}")
        analyzer.close()
        
    except Exception as e:
        print(f"{Fore.RED}Error during analysis: {str(e)}{Style.RESET_ALL}")
        sys.exit(1)

if __name__ == "__main__":
    main()