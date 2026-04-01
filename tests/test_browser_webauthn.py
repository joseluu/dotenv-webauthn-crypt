"""
Prototype: Use a local browser as the WebAuthn client for platform credentials.

Flow:
1. Start HTTP server on localhost:8580
2. Open browser to the page
3. Browser calls navigator.credentials.create() or .get() with platform attachment
4. JavaScript POSTs the result back to the server
5. Python receives the credential data and prints it

Usage:
    python test_browser_webauthn.py create
    python test_browser_webauthn.py sign
"""

import http.server
import json
import base64
import hashlib
import sys
import threading
import webbrowser
import urllib.parse

PORT = 8580
RP_ID = "localhost"
RP_NAME = "dotenv-webauthn-crypt"
USER_NAME = "default_user"
USER_DISPLAY = "Default User"
# Fixed challenge for deterministic key derivation
FIXED_CHALLENGE = hashlib.sha256(b"dotenv-webauthn-fixed-challenge-v2").digest()

# Will be filled by the POST handler
result_data = None
server_should_stop = threading.Event()

HTML_CREATE = """<!DOCTYPE html>
<html>
<head><title>WebAuthn Create - dotenv-webauthn-crypt</title></head>
<body>
<h2>Creating platform credential...</h2>
<p id="status">Waiting for Windows Hello...</p>
<script>
async function createCredential() {
    const status = document.getElementById('status');
    try {
        const challenge = new Uint8Array(CHALLENGE_BYTES);
        const credential = await navigator.credentials.create({
            publicKey: {
                rp: { id: "localhost", name: "RP_NAME_HERE" },
                user: {
                    id: new TextEncoder().encode("USER_NAME_HERE"),
                    name: "USER_NAME_HERE",
                    displayName: "USER_DISPLAY_HERE"
                },
                challenge: challenge,
                pubKeyCredParams: [{ type: "public-key", alg: -7 }],
                authenticatorSelection: {
                    authenticatorAttachment: "platform",
                    userVerification: "required",
                    residentKey: "discouraged"
                },
                timeout: 120000,
                attestation: "none"
            }
        });

        // Extract data
        const credentialId = Array.from(new Uint8Array(credential.rawId));
        const attestationObject = Array.from(new Uint8Array(credential.response.attestationObject));
        const clientDataJSON = Array.from(new Uint8Array(credential.response.clientDataJSON));
        const authData = Array.from(new Uint8Array(credential.response.getAuthenticatorData()));

        const result = {
            credential_id: credentialId,
            attestation_object: attestationObject,
            client_data_json: clientDataJSON,
            authenticator_data: authData,
            transport: credential.response.getTransports ? credential.response.getTransports() : []
        };

        status.textContent = 'Success! Sending to server...';
        await fetch('/result', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(result)
        });
        status.textContent = 'Done! You can close this tab.';
        document.body.style.backgroundColor = '#d4edda';
    } catch (err) {
        status.textContent = 'Error: ' + err.message;
        document.body.style.backgroundColor = '#f8d7da';
        await fetch('/result', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({error: err.message})
        });
    }
}
createCredential();
</script>
</body>
</html>"""

HTML_SIGN = """<!DOCTYPE html>
<html>
<head><title>WebAuthn Sign - dotenv-webauthn-crypt</title></head>
<body>
<h2>Authenticating with platform credential...</h2>
<p id="status">Waiting for Windows Hello...</p>
<script>
async function getAssertion() {
    const status = document.getElementById('status');
    try {
        const challenge = new Uint8Array(CHALLENGE_BYTES);
        const credentialId = new Uint8Array(CREDENTIAL_ID_BYTES);

        const assertion = await navigator.credentials.get({
            publicKey: {
                rpId: "localhost",
                challenge: challenge,
                allowCredentials: [{
                    type: "public-key",
                    id: credentialId.buffer,
                    transports: ["internal", "hybrid"]
                }],
                userVerification: "required",
                timeout: 120000
            }
        });

        const result = {
            credential_id: Array.from(new Uint8Array(assertion.rawId)),
            signature: Array.from(new Uint8Array(assertion.response.signature)),
            authenticator_data: Array.from(new Uint8Array(assertion.response.authenticatorData)),
            client_data_json: Array.from(new Uint8Array(assertion.response.clientDataJSON))
        };

        status.textContent = 'Success! Sending to server...';
        await fetch('/result', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(result)
        });
        status.textContent = 'Done! You can close this tab.';
        document.body.style.backgroundColor = '#d4edda';
    } catch (err) {
        status.textContent = 'Error: ' + err.message;
        document.body.style.backgroundColor = '#f8d7da';
        await fetch('/result', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({error: err.message})
        });
    }
}
getAssertion();
</script>
</body>
</html>"""


def bytes_to_js_array(b):
    """Convert bytes to a JavaScript array literal string."""
    return "[" + ",".join(str(x) for x in b) + "]"


class WebAuthnHandler(http.server.BaseHTTPRequestHandler):
    def __init__(self, *args, mode="create", credential_id=None, **kwargs):
        self.mode = mode
        self.credential_id = credential_id
        super().__init__(*args, **kwargs)

    def do_GET(self):
        if self.path == "/create":
            html = HTML_CREATE
            html = html.replace("CHALLENGE_BYTES", bytes_to_js_array(FIXED_CHALLENGE))
            html = html.replace("RP_NAME_HERE", RP_NAME)
            html = html.replace("USER_NAME_HERE", USER_NAME)
            html = html.replace("USER_DISPLAY_HERE", USER_DISPLAY)
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(html.encode())

        elif self.path == "/sign":
            if not self.credential_id:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b"No credential_id provided")
                return
            html = HTML_SIGN
            html = html.replace("CHALLENGE_BYTES", bytes_to_js_array(FIXED_CHALLENGE))
            html = html.replace("CREDENTIAL_ID_BYTES", bytes_to_js_array(self.credential_id))
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(html.encode())
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        global result_data
        if self.path == "/result":
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length)
            result_data = json.loads(body)
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"OK")
            server_should_stop.set()
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        # Suppress default logging
        pass


def run_webauthn_browser(mode="create", credential_id=None):
    """Start server, open browser, wait for result."""
    global result_data
    result_data = None
    server_should_stop.clear()

    def handler_factory(*args, **kwargs):
        return WebAuthnHandler(*args, mode=mode, credential_id=credential_id, **kwargs)

    server = http.server.HTTPServer(("127.0.0.1", PORT), handler_factory)
    server.timeout = 1  # 1s poll interval

    url = f"http://localhost:{PORT}/{mode}"
    print(f"Starting server on http://localhost:{PORT}")
    print(f"Opening browser to {url}")
    webbrowser.open(url)

    # Serve until we get a result or timeout
    import time
    deadline = time.time() + 120  # 2 min timeout
    while not server_should_stop.is_set() and time.time() < deadline:
        server.handle_request()

    server.server_close()
    return result_data


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "create"

    if mode == "create":
        print("=== WebAuthn Platform Credential Creation (via browser) ===")
        print(f"RP ID: {RP_ID}")
        print(f"Challenge: {FIXED_CHALLENGE.hex()}")
        print()

        result = run_webauthn_browser("create")

        if not result:
            print("ERROR: No response received (timeout)")
            return

        if "error" in result:
            print(f"ERROR: {result['error']}")
            return

        cred_id = bytes(result["credential_id"])
        auth_data = bytes(result["authenticator_data"])

        print(f"Credential ID ({len(cred_id)} bytes): {base64.b64encode(cred_id).decode()}")
        print(f"Authenticator Data ({len(auth_data)} bytes)")
        print(f"Transports: {result.get('transport', [])}")

        # Save credential_id for sign test
        with open("test_browser_credential.json", "w") as f:
            json.dump({
                "credential_id": result["credential_id"],
                "authenticator_data": result["authenticator_data"],
            }, f)
        print("\nSaved to test_browser_credential.json")
        print("Run 'python test_browser_webauthn.py sign' to test authentication.")

    elif mode == "sign":
        print("=== WebAuthn Platform Assertion (via browser) ===")

        try:
            with open("test_browser_credential.json") as f:
                saved = json.load(f)
        except FileNotFoundError:
            print("ERROR: No credential found. Run 'create' first.")
            return

        credential_id = bytes(saved["credential_id"])
        print(f"Credential ID: {base64.b64encode(credential_id).decode()}")
        print(f"Challenge: {FIXED_CHALLENGE.hex()}")
        print()

        result = run_webauthn_browser("sign", credential_id)

        if not result:
            print("ERROR: No response received (timeout)")
            return

        if "error" in result:
            print(f"ERROR: {result['error']}")
            return

        signature = bytes(result["signature"])
        auth_data = bytes(result["authenticator_data"])

        print(f"Signature ({len(signature)} bytes): {signature.hex()}")
        print(f"Authenticator Data ({len(auth_data)} bytes): {auth_data.hex()}")

        # Derive a master key from the public key (same approach as core.py)
        # For now just show the raw data
        print("\nRaw result keys:", list(result.keys()))
        print("Sign test complete!")

    else:
        print(f"Usage: python test_browser_webauthn.py [create|sign]")


if __name__ == "__main__":
    main()
