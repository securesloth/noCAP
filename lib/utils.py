import os
from pathlib import Path
from colorama import init, Fore, Style 

# Initialize colorama
init()

# Constants moved to utils.py for easy access
GRAPH_API_VERSION = "v1.0"
GRAPH_CLIENT_ID = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"
DEFAULT_OUTPUT_DIR = "output"

def get_output_directory():
    directory = input("Enter output directory (press Enter for default): ").strip()
    if not directory:
        directory = DEFAULT_OUTPUT_DIR
    path = Path(directory)
    path.mkdir(parents=True, exist_ok=True)
    return path

def print_color(text, color):
    """Helper function for colored output"""
    print(f"{color}{text}{Style.RESET_ALL}")

ORANGE_256 = "\033[38;2;255;165;0m"  # 208 is a decent orange in 256-color mode
RESET = "\033[0m"

def print_orange(text):
    print(f"{ORANGE_256}{text}{RESET}")