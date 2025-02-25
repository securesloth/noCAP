from lib.auth import authenticate_graph
from lib.fetch import fetch_conditional_access_policies, fetch_current_user
from lib.export import export_policies
from lib.analyze import analyze_policies
from lib.utils import get_output_directory
from lib.utils import print_color
from colorama import Fore
import logging
import argparse
import sys


def print_banner():
    return r"""
                    _________    ____ 
       ____  ____  / ____/   |  / __ \
      / __ \/ __ \/ /   / /| | / /_/ /
     / / / / /_/ / /___/ ___ |/ ____/ 
    /_/ /_/\____/\____/_/  |_/_/      
                                   
                    by @securesloth"""

def main():
    parser = argparse.ArgumentParser(
    description=print_banner(),
    formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        '--devicecode',
        action='store_true',
        help='Authenticate using device code flow with Microsoft'
    )
    # If no arguments are passed, print help and exit
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)
    
    args = parser.parse_args()

    print(print_banner())
    print_color("\n\nStarting Conditional Access Policy Audit...\n", Fore.CYAN)

    try:
        directory = get_output_directory()
        access_token = authenticate_graph()
        
        # Fetch and display current user
        current_user = fetch_current_user(access_token)
        print_color(f"\nAuthenticated as: {current_user}\n", Fore.GREEN)
        
        policies = fetch_conditional_access_policies(access_token)

        if policies:
            export_policies(policies, directory, access_token)
            analyze_policies(policies)
        else:
            print("No policies retrieved or an error occurred.")
    except Exception as e:
        print(f"An error occurred: {e}")
        logging.error(f"Error in main execution: {e}")

if __name__ == "__main__":
    main()
