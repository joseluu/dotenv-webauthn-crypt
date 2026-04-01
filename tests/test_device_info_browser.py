"""
Test: Extract device information from a cross-platform WebAuthn credential.

Uses the browser as WebAuthn client with "cross-platform" attachment and
"direct" attestation to get maximum device info (AAGUID, attestation cert).

Usage:
    python tests/test_device_info_browser.py
"""

import http.server
import json
import base64
import hashlib
import os
import sys
import threading
import webbrowser
import struct

PORT = 8581
CHALLENGE = hashlib.sha256(b"device-info-test-challenge").digest()

result_data = None
server_should_stop = threading.Event()


def bytes_to_js_array(b):
    return "[" + ",".join(str(x) for x in b) + "]"


HTML_PAGE = """<!DOCTYPE html>
<html>
<head><title>WebAuthn Device Info Test</title></head>
<body>
<h2>Cross-platform credential creation (phone/security key)</h2>
<p id="status">Waiting for authenticator...</p>
<pre id="log" style="background:#f0f0f0;padding:10px;max-height:400px;overflow:auto"></pre>
<script>
function log(msg) {
    document.getElementById('log').textContent += msg + '\\n';
}
async function run() {
    const status = document.getElementById('status');
    try {
        const challenge = new Uint8Array(CHALLENGE_BYTES);
        log('Creating credential with cross-platform + direct attestation...');
        const credential = await navigator.credentials.create({
            publicKey: {
                rp: { id: "localhost", name: "dotenv-webauthn-crypt" },
                user: {
                    id: new TextEncoder().encode("device_info_test"),
                    name: "device_info_test",
                    displayName: "Device Info Test"
                },
                challenge: challenge,
                pubKeyCredParams: [{ type: "public-key", alg: -7 }],
                authenticatorSelection: {
                    authenticatorAttachment: "cross-platform",
                    userVerification: "required",
                    residentKey: "discouraged"
                },
                timeout: 300000,
                attestation: "direct"
            }
        });

        const rawId = Array.from(new Uint8Array(credential.rawId));
        const attestationObject = Array.from(new Uint8Array(credential.response.attestationObject));
        const clientDataJSON = new TextDecoder().decode(credential.response.clientDataJSON);
        const authData = Array.from(new Uint8Array(credential.response.getAuthenticatorData()));
        const transports = credential.response.getTransports ? credential.response.getTransports() : [];
        const pubKeyDer = credential.response.getPublicKey ? Array.from(new Uint8Array(credential.response.getPublicKey())) : [];
        const pubKeyAlg = credential.response.getPublicKeyAlgorithm ? credential.response.getPublicKeyAlgorithm() : null;
        const authAttachment = credential.authenticatorAttachment || "unknown";

        log('Credential type: ' + credential.type);
        log('Authenticator attachment: ' + authAttachment);
        log('Transports: ' + JSON.stringify(transports));
        log('Credential ID length: ' + rawId.length);
        log('AuthData length: ' + authData.length);
        log('AttestationObject length: ' + attestationObject.length);
        log('Public key algorithm: ' + pubKeyAlg);

        const result = {
            credential_id: rawId,
            attestation_object: attestationObject,
            authenticator_data: authData,
            client_data_json: clientDataJSON,
            transports: transports,
            public_key_der: pubKeyDer,
            public_key_alg: pubKeyAlg,
            authenticator_attachment: authAttachment
        };

        status.textContent = 'Success! Sending to server...';
        await fetch('/result', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(result)
        });
        status.textContent = 'Done! Check the terminal for parsed results.';
        document.body.style.backgroundColor = '#d4edda';
    } catch (err) {
        status.textContent = 'Error: ' + err.message;
        log('ERROR: ' + err.message + '\\n' + err.stack);
        document.body.style.backgroundColor = '#f8d7da';
        await fetch('/result', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({error: err.message})
        });
    }
}
run();
</script>
</body>
</html>"""


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        html = HTML_PAGE.replace("CHALLENGE_BYTES", bytes_to_js_array(CHALLENGE))
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(html.encode())

    def do_POST(self):
        global result_data
        if self.path == "/result":
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length)
            result_data = json.loads(body)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"OK")
            server_should_stop.set()

    def log_message(self, format, *args):
        pass


def parse_aaguid(auth_data):
    """Extract AAGUID from authenticator data bytes 37-52."""
    if len(auth_data) < 53:
        return None
    flags = auth_data[32]
    if not (flags & 0x40):  # AT flag
        return None
    aaguid = auth_data[37:53]
    return aaguid


def format_guid(b):
    """Format 16 bytes as a standard GUID string."""
    return (
        b[:4].hex() + "-" +
        b[4:6].hex() + "-" +
        b[6:8].hex() + "-" +
        b[8:10].hex() + "-" +
        b[10:16].hex()
    )


def parse_attestation_object(att_obj_bytes):
    """Decode CBOR attestation object and look for x5c certificates."""
    try:
        import cbor2
        obj = cbor2.loads(bytes(att_obj_bytes))
        return obj
    except ImportError:
        print("  (install cbor2 for full attestation parsing: pip install cbor2)")
        return None
    except Exception as e:
        print(f"  CBOR decode error: {e}")
        return None


def main():
    global result_data
    result_data = None
    server_should_stop.clear()

    print("=== WebAuthn Device Info Test (via browser) ===")
    print(f"Starting server on http://localhost:{PORT}")
    print()

    server = http.server.HTTPServer(("127.0.0.1", PORT), Handler)
    server.timeout = 1

    # Launch Chrome with its own WebAuthn UI (bypass Windows native dialog)
    # Chrome's own caBLE implementation doesn't depend on Microsoft account
    import subprocess, tempfile
    chrome = r"C:\Program Files\Google\Chrome\Application\chrome.exe"
    tmp_profile = os.path.join(tempfile.gettempdir(), "chrome_webauthn_test")
    url = f"http://localhost:{PORT}/"
    print(f"Launching Chrome with --disable-features=WebAuthenticationUseNewWindowsHelloApi")
    print(f"Temp profile: {tmp_profile}")
    print(f"URL: {url}")
    print()
    subprocess.Popen([
        chrome,
        "--disable-features=WebAuthenticationUseNewWindowsHelloApi",
        "--enable-features=WebAuthenticationHybridTransport",
        url
    ])

    import time
    deadline = time.time() + 300
    while not server_should_stop.is_set() and time.time() < deadline:
        server.handle_request()
    server.server_close()

    if not result_data:
        print("ERROR: No response (timeout)")
        return

    if "error" in result_data:
        print(f"ERROR: {result_data['error']}")
        return

    # --- Parse results ---
    print("=" * 60)
    print("CREDENTIAL CREATED SUCCESSFULLY")
    print("=" * 60)

    auth_data = bytes(result_data["authenticator_data"])
    cred_id = bytes(result_data["credential_id"])

    print(f"\n--- Browser-reported info ---")
    print(f"  Authenticator attachment: {result_data.get('authenticator_attachment', '?')}")
    print(f"  Transports:              {result_data.get('transports', [])}")
    print(f"  Public key algorithm:    {result_data.get('public_key_alg', '?')}")
    print(f"  Credential ID:           {base64.urlsafe_b64encode(cred_id).decode()} ({len(cred_id)} bytes)")

    print(f"\n--- AuthenticatorData parsed ---")
    print(f"  RP ID hash:              {auth_data[:32].hex()}")
    flags = auth_data[32]
    print(f"  Flags:                   0x{flags:02x}")
    print(f"    User Present:          {'YES' if flags & 0x01 else 'NO'}")
    print(f"    User Verified:         {'YES' if flags & 0x04 else 'NO'}")
    print(f"    Attested Credential:   {'YES' if flags & 0x40 else 'NO'}")
    print(f"    Extensions:            {'YES' if flags & 0x80 else 'NO'}")
    counter = struct.unpack(">I", auth_data[33:37])[0]
    print(f"  Sign counter:            {counter}")

    aaguid = parse_aaguid(auth_data)
    if aaguid:
        guid_str = format_guid(aaguid)
        all_zero = all(b == 0 for b in aaguid)
        print(f"  AAGUID:                  {guid_str}")
        if all_zero:
            print(f"  AAGUID note:             ALL ZEROS — authenticator did not disclose its model")
        else:
            print(f"  -> Look up this AAGUID:  https://passkeydeveloper.github.io/passkey-authenticator-aaguids/")

    # --- Parse attestation object (CBOR) ---
    att_obj = parse_attestation_object(result_data["attestation_object"])
    if att_obj:
        print(f"\n--- Attestation Object ---")
        fmt = att_obj.get("fmt", "?")
        print(f"  Format:                  {fmt}")
        att_stmt = att_obj.get("attStmt", {})
        print(f"  Statement keys:          {list(att_stmt.keys())}")

        if "x5c" in att_stmt:
            certs = att_stmt["x5c"]
            print(f"  Certificates (x5c):      {len(certs)} cert(s)")
            for i, cert_bytes in enumerate(certs):
                print(f"    Cert {i}: {len(cert_bytes)} bytes")
                # Try to parse with cryptography lib
                try:
                    from cryptography import x509
                    cert = x509.load_der_x509_certificate(cert_bytes)
                    print(f"      Subject:  {cert.subject.rfc4514_string()}")
                    print(f"      Issuer:   {cert.issuer.rfc4514_string()}")
                    print(f"      Serial:   {cert.serial_number}")
                    print(f"      NotBefore: {cert.not_valid_before_utc}")
                    print(f"      NotAfter:  {cert.not_valid_after_utc}")
                    # Look for FIDO extensions
                    for ext in cert.extensions:
                        print(f"      Extension: {ext.oid.dotted_string} ({ext.oid._name})")
                except Exception as e:
                    print(f"      (parse error: {e})")
        else:
            print(f"  No x5c certificates in attestation (format: {fmt})")

        if "sig" in att_stmt:
            sig = att_stmt["sig"]
            print(f"  Signature:               {len(sig)} bytes")

    # Save raw data for further analysis
    with open("tests/test_device_info_result.json", "w") as f:
        json.dump({
            "credential_id_b64": base64.urlsafe_b64encode(cred_id).decode(),
            "aaguid": format_guid(aaguid) if aaguid else None,
            "transports": result_data.get("transports", []),
            "authenticator_attachment": result_data.get("authenticator_attachment", ""),
            "attestation_format": att_obj.get("fmt") if att_obj else None,
        }, f, indent=2)
    print(f"\nSaved summary to tests/test_device_info_result.json")


if __name__ == "__main__":
    main()
