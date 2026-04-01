import os
import sys
import argparse
from .core import (load_dotenv, init_credential, encrypt_file,
                   get_credential_info, fetch_aaguid_info)

DEVICE_HINTS = {
    "local": "client-device",
    "phone": "hybrid",
    "usb": "security-key",
}

DEVICE_LABELS = {
    "local": "Windows Hello (fingerprint/PIN)",
    "phone": "Smartphone via QR code (hybrid)",
    "usb": "USB security key (FIDO2)",
}


def _print_credential_info(meta, aaguid_info=None):
    """Print credential metadata in a readable format."""
    import base64
    cred_b64 = base64.b64encode(meta['credential_id']).decode()
    print(f"  Credential ID : {cred_b64[:40]}...")
    print(f"  Domain (RP_ID): {meta.get('rp_id', 'unknown')}")
    print(f"  User name     : {meta.get('user_name', 'unknown')}")
    device = meta.get('device', 'unknown')
    print(f"  Device        : {device} ({DEVICE_LABELS.get(device, device)})")
    print(f"  Transport     : {meta.get('transport', 'unknown')}")
    aaguid = meta.get('aaguid', '')
    print(f"  AAGUID        : {aaguid or '(none)'}")
    if aaguid_info:
        print(f"  Authenticator : {aaguid_info.get('name', 'unknown')}")
    print(f"  Created at    : {meta.get('created_at', 'unknown')}")


def main():
    parser = argparse.ArgumentParser(description="dotenv-webauthn-crypt CLI")
    parser.add_argument("command", choices=["encrypt", "decrypt", "init", "info", "rekey", "version"])
    parser.add_argument("env_path", nargs="?", default=".env")
    parser.add_argument("--user", help="User name for init", default="default_user")
    parser.add_argument("--device", choices=["local", "phone", "usb"],
                        default=None,
                        help="Authentication device: local (Windows Hello), phone (QR code), usb (security key)")

    args = parser.parse_args()

    from . import _webauthn
    version = _webauthn.get_version()
    print(f"dotenv-webauthn-crypt v{version}")

    if args.command == "version":
        sys.exit(0)

    try:
        if args.command == "info":
            meta = get_credential_info()
            print("\n--- Credential Information ---")
            aaguid = meta.get('aaguid', '')
            aaguid_info = None
            if aaguid:
                print(f"  Fetching authenticator info for AAGUID {aaguid}...")
                aaguid_info = fetch_aaguid_info(aaguid)
                if not aaguid_info:
                    print("  (not found in AAGUID database)")
            _print_credential_info(meta, aaguid_info)

        elif args.command == "init":
            status = _webauthn.get_platform_status()
            errors = set(status.get('ngc_errors', []))

            critical = errors & {"HardwareFailure", "PinExistsFailure"}
            session = errors & {"RemoteSessionFailure"}
            policy = errors & {"PolicyFailure"}
            bt_available = status.get('bluetooth_available', False)
            net_available = status.get('network_available', False)
            can_local = status['platform_available'] and not critical and not session
            can_phone = bt_available and net_available

            print(f"\n--- Platform Authentication Status ---")
            print(f"  WebAuthn API version: {status['api_version']}")
            print(f"  Platform authenticator: {'available' if status['platform_available'] else 'NOT available'}")
            print(f"  Bluetooth: {'available' if bt_available else 'NOT available'}")
            print(f"  Network: {'available' if net_available else 'NOT available'}")

            print()
            if critical:
                print("  [BLOCKED] Windows Hello cannot work:")
                if "HardwareFailure" in critical:
                    print("    - TPM hardware failure or not available")
                if "PinExistsFailure" in critical:
                    print("    - No PIN configured. Set one in Settings > Accounts > Sign-in options.")
            elif session:
                print("  [BLOCKED] Remote desktop session detected.")
                print("    Windows Hello requires a local session.")
            elif policy and not status['platform_available']:
                print("  [BLOCKED] Windows Hello is disabled by policy.")
                print("    Enable PassportForWork in registry or group policy.")

            if not args.device:
                print("  Choose an authentication device with --device:\n")
                if can_local:
                    print("    --device local   Windows Hello (fingerprint/PIN)")
                    print("                     Credential stored in the local TPM.")
                    print("                     Fast, no extra hardware needed.\n")
                else:
                    print("    --device local   [UNAVAILABLE] Windows Hello not ready.\n")

                if can_phone:
                    print("    --device phone   Smartphone via QR code (hybrid)")
                    print("                     Credential stored on your phone.")
                    print("                     Requires Bluetooth + network.\n")
                else:
                    reasons = []
                    if not bt_available:
                        reasons.append("Bluetooth off")
                    if not net_available:
                        reasons.append("no network")
                    print(f"    --device phone   [UNAVAILABLE] {', '.join(reasons)}.\n")

                print("    --device usb     USB security key (FIDO2)")
                print("                     Credential stored on the key.")
                print("                     Requires a compatible USB key.\n")

                print("  Example: dotenv-webauthn-crypt-cli init --device local --user myname")
                sys.exit(0)

            hint = DEVICE_HINTS[args.device]
            print(f"  Device: {args.device}")
            print()
            init_credential(args.user, hint=hint)

        elif args.command == "encrypt":
            encrypt_file(args.env_path)
        elif args.command == "decrypt":
            load_dotenv(args.env_path)
            with open(args.env_path, "r") as f:
                for line in f:
                    stripped = line.strip()
                    if stripped and not stripped.startswith('#') and "=" in stripped:
                        key, _ = stripped.split("=", 1)
                        if key in os.environ:
                            print(f"{key}={os.environ[key]}")
        else:
            print(f"Command '{args.command}' not yet implemented.")
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
