import sys
import argparse
from .core import load_dotenv, init_credential, encrypt_file

def main():
    parser = argparse.ArgumentParser(description="dotenv-webauthn-crypt CLI")
    parser.add_argument("command", choices=["encrypt", "decrypt", "init", "rekey"])
    parser.add_argument("env_path", nargs="?", default=".env")
    parser.add_argument("--user", help="User name for init", default="default_user")
    
    args = parser.parse_args()
    
    try:
        if args.command == "init":
            init_credential(args.user)
        elif args.command == "encrypt":
            encrypt_file(args.env_path)
        elif args.command == "decrypt":
            # Just to verify load_dotenv logic via CLI
            load_dotenv(args.env_path)
            print("Loaded (decrypted) variables into environment.")
            # Show decrypted values for verification
            with open(args.env_path, "r") as f:
                for line in f:
                    if "=" in line:
                        key, _ = line.strip().split("=", 1)
                        import os
                        print(f"{key}={os.environ.get(key)}")
        else:
            print(f"Command '{args.command}' not yet implemented.")
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
