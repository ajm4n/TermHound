#!/usr/bin/env python3
import argparse
import sys
from termhound.analyzer import TermHoundAnalyzer

def main():
    parser = argparse.ArgumentParser(description='TermHound - AD Security Analysis Tool')
    parser.add_argument('--uri', required=True, help='Neo4j database URI')
    parser.add_argument('--username', required=True, help='Neo4j username')
    parser.add_argument('--password', required=True, help='Neo4j password')
    parser.add_argument('--output', required=True, help='Output report file')
    parser.add_argument('--owned', nargs='+', help='List of owned usernames')
    parser.add_argument('--quiet', action='store_true', help='Suppress terminal output')
    
    args = parser.parse_args()
    
    try:
        analyzer = TermHoundAnalyzer(
            args.uri, 
            args.username, 
            args.password,
            args.owned
        )
        
        analyzer.generate_report(args.output)
        print(f"\nAnalysis complete! Report saved to: {args.output}")
        analyzer.close()
        
    except Exception as e:
        print(f"Error during analysis: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
