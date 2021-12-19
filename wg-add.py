import sys
import os
import pathlib

def main():
    # Check if program is being run as root
    if not 'SUDO_UID' in os.environ.keys():
        print("You need to execute this program as root")
        sys.exit(1)
    

if __name__ == "__main__":
    main()