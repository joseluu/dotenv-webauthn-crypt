import os
import sys
import argparse
import importlib.metadata
from .core import load_dotenv, init_credential, encrypt_file

def main():
    parser = argparse.ArgumentParser(description="dotenv-webauthn-crypt CLI")
    parser.add_argument("command", choices=["encrypt", "decrypt", "init", "rekey", "version"])
    parser.add_argument("env_path", nargs="?", default=".env")
    parser.add_argument("--user", help="User name for init", default="default_user")
    
    args = parser.parse_args()

    from . import _webauthn
    version = _webauthn.get_version()
    print(f"dotenv-webauthn-crypt v{version}")

    if args.command == "version":
        sys.exit(0)

    try:
        if args.command == "init":
            init_credential(args.user)
        elif args.command == "encrypt":
            encrypt_file(args.env_path)
        elif args.command == "decrypt":
            load_dotenv(args.env_path)
            for line in open(args.env_path, "r"):
                if "=" in line:
                    key, _ = line.strip().split("=", 1)
                    if key in os.environ:
                        print(f"{key}={os.environ[key]}")
        else:
            print(f"Command '{args.command}' not yet implemented.")
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
