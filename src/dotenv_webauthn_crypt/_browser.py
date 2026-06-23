"""Browser-based WebAuthn backend (Linux / macOS / WSL).

This module provides a pure-Python implementation of the same interface as the
native Windows ``_webauthn`` C++ extension, but it delegates the actual WebAuthn
operations to a local web browser via ``navigator.credentials.create()`` /
``navigator.credentials.get()``.

Why a browser?  Unlike Windows, Linux has no single system API that exposes the
platform authenticator (fingerprint reader / TPM).  Every modern browser, on the
other hand, ships a complete WebAuthn client that talks to whatever the OS makes
available: a platform authenticator (fingerprint/PIN), a roaming USB FIDO2 key,
or a phone over hybrid/QR.  By driving the browser we get all of those for free.

Under WSL the Python HTTP server is reachable from the Windows host on
``http://localhost:<port>`` (WSL2 localhost forwarding), so the *Windows* browser
— and therefore Windows Hello / the fingerprint reader attached to Windows — can
satisfy the prompt even though the library itself runs inside Linux.

Interface (mirrors the native module so ``core.py`` is platform-agnostic):

    make_credential(rp_id, user_name, hint="") -> dict
        {credential_id, authenticator_data, transport, aaguid}
    get_assertion(rp_id, credential_id, challenge, hint="") -> dict
        {signature, authenticator_data, client_data_hash, credential_id}
    get_platform_status() -> dict
    get_version() -> str

The one semantic difference from the native module is that ``get_assertion``
also returns ``client_data_hash``: in the browser the signed client-data hash is
``SHA256(clientDataJSON)`` (a real JSON object), not ``SHA256(challenge)``.  The
backend layer relies on this field so public-key recovery works identically on
every platform.
"""

import os
import sys
import json
import time
import socket
import hashlib
import struct
import shutil
import threading
import subprocess
import http.server

# WebAuthn requires the page to be served from a "secure context".  http://localhost
# is treated as secure by every browser, so plain HTTP on localhost is fine and we
# avoid the pain of generating a trusted TLS certificate.
RP_ID = "localhost"
RP_NAME = "dotenv-webauthn-crypt"
DEFAULT_PORT = 8580

# Map the device hints used by the CLI to a browser authenticatorAttachment.
#   local        -> platform authenticator (fingerprint / PIN / TPM)
#   phone / usb  -> cross-platform (roaming) authenticator
_ATTACHMENT_BY_HINT = {
    "client-device": "platform",
    "hybrid": "cross-platform",
    "security-key": "cross-platform",
}


def get_version() -> str:
    try:
        from importlib.metadata import version, PackageNotFoundError
        try:
            return version("dotenv-webauthn-crypt")
        except PackageNotFoundError:
            pass
    except Exception:
        pass
    return "0.0.0+browser"


def _is_wsl() -> bool:
    if sys.platform != "linux":
        return False
    try:
        with open("/proc/version", "r") as f:
            return "microsoft" in f.read().lower()
    except OSError:
        return False


def _open_browser(url: str) -> None:
    """Open *url* in the user's browser, with a WSL-aware fallback chain.

    The URL is always printed so the user can open it manually if every
    automated attempt fails (e.g. a headless server, or an unusual desktop).
    """
    print(f"\n  >> Open this URL in a browser to authenticate:\n     {url}\n")

    # On WSL the Linux side usually has no browser installed, but the Windows
    # default browser can reach the server through localhost forwarding.
    if _is_wsl():
        # Run from a Windows-accessible cwd to avoid the cmd.exe UNC-path warning.
        win_cwd = "/mnt/c" if os.path.isdir("/mnt/c") else None
        for cmd in (
            ["cmd.exe", "/c", "start", "", url],
            ["powershell.exe", "-NoProfile", "-Command", f"Start-Process '{url}'"],
            ["wslview", url],
        ):
            if shutil.which(cmd[0]):
                try:
                    subprocess.Popen(cmd, cwd=win_cwd,
                                     stdout=subprocess.DEVNULL,
                                     stderr=subprocess.DEVNULL)
                    return
                except OSError:
                    continue

    # Native Linux / macOS desktop.
    try:
        import webbrowser
        webbrowser.open(url)
    except Exception:
        pass


def _bytes_to_js_array(b) -> str:
    return "[" + ",".join(str(x) for x in bytes(b)) + "]"


def _parse_aaguid(auth_data: bytes) -> str:
    """Extract the AAGUID from attested credential data (create only)."""
    if len(auth_data) >= 53 and (auth_data[32] & 0x40):
        raw = auth_data[37:53]
        hexes = raw.hex()
        return f"{hexes[0:8]}-{hexes[8:12]}-{hexes[12:16]}-{hexes[16:20]}-{hexes[20:32]}"
    return ""


_PAGE = """<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>__TITLE__</title>
<style>
  body {{ font-family: sans-serif; max-width: 40em; margin: 4em auto; padding: 0 1em; }}
  #status {{ font-size: 1.1em; }}
  .ok {{ color: #155724; }} .err {{ color: #721c24; }}
</style>
</head>
<body>
<h2>__HEADING__</h2>
<p id="status">Waiting for your authenticator (fingerprint / PIN / security key)...</p>
<script>
function b(arr) {{ return new Uint8Array(arr); }}
async function post(obj) {{
  await fetch('/result', {{ method:'POST', headers:{{'Content-Type':'application/json'}},
                            body: JSON.stringify(obj) }});
}}
async function run() {{
  const status = document.getElementById('status');
  try {{
    const result = await ACTION();
    status.textContent = 'Success — you can close this tab.';
    status.className = 'ok';
    await post(result);
  }} catch (err) {{
    status.textContent = 'Error: ' + err.message;
    status.className = 'err';
    await post({{ error: String(err && err.message || err) }});
  }}
}}
run();
</script>
</body>
</html>"""

_CREATE_ACTION = """async function() {
  const credential = await navigator.credentials.create({
    publicKey: {
      rp: { id: "__RP_ID__", name: "__RP_NAME__" },
      user: {
        id: new TextEncoder().encode("__USER_NAME__"),
        name: "__USER_NAME__",
        displayName: "__USER_NAME__"
      },
      challenge: b(__CHALLENGE__),
      pubKeyCredParams: [{ type: "public-key", alg: -7 }],
      authenticatorSelection: __AUTHSEL__,
      timeout: 120000,
      attestation: "none"
    }
  });
  return {
    credential_id: Array.from(new Uint8Array(credential.rawId)),
    authenticator_data: Array.from(new Uint8Array(credential.response.getAuthenticatorData())),
    client_data_json: Array.from(new Uint8Array(credential.response.clientDataJSON)),
    transport: credential.response.getTransports ? credential.response.getTransports() : []
  };
}"""

_GET_ACTION = """async function() {
  const assertion = await navigator.credentials.get({
    publicKey: {
      rpId: "__RP_ID__",
      challenge: b(__CHALLENGE__),
      allowCredentials: [{
        type: "public-key",
        id: b(__CREDENTIAL_ID__).buffer,
        transports: ["internal", "hybrid", "usb", "nfc", "ble"]
      }],
      userVerification: "required",
      timeout: 120000
    }
  });
  return {
    credential_id: Array.from(new Uint8Array(assertion.rawId)),
    signature: Array.from(new Uint8Array(assertion.response.signature)),
    authenticator_data: Array.from(new Uint8Array(assertion.response.authenticatorData)),
    client_data_json: Array.from(new Uint8Array(assertion.response.clientDataJSON))
  };
}"""


def _render_page(mode: str, *, challenge, user_name="", credential_id=None, hint="") -> str:
    if mode == "create":
        attachment = _ATTACHMENT_BY_HINT.get(hint)
        authsel = {"userVerification": "required", "residentKey": "discouraged"}
        if attachment:
            authsel["authenticatorAttachment"] = attachment
        action = (_CREATE_ACTION
                  .replace("__RP_ID__", RP_ID)
                  .replace("__RP_NAME__", RP_NAME)
                  .replace("__USER_NAME__", user_name)
                  .replace("__CHALLENGE__", _bytes_to_js_array(challenge))
                  .replace("__AUTHSEL__", json.dumps(authsel)))
        page = (_PAGE.replace("__TITLE__", "WebAuthn — register")
                     .replace("__HEADING__", "Registering a new credential"))
    else:
        action = (_GET_ACTION
                  .replace("__RP_ID__", RP_ID)
                  .replace("__CHALLENGE__", _bytes_to_js_array(challenge))
                  .replace("__CREDENTIAL_ID__", _bytes_to_js_array(credential_id)))
        page = (_PAGE.replace("__TITLE__", "WebAuthn — authenticate")
                     .replace("__HEADING__", "Authenticating"))
    return page.replace("ACTION", action)


def _run_browser_flow(html: str, timeout: int = 120) -> dict:
    """Serve *html* once, drive the browser, and return the POSTed JSON result."""
    result_holder = {}
    done = threading.Event()

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path in ("/", "/create", "/sign"):
                body = html.encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            else:
                self.send_response(404)
                self.end_headers()

        def do_POST(self):
            if self.path == "/result":
                length = int(self.headers.get("Content-Length", 0))
                payload = self.rfile.read(length)
                try:
                    result_holder.update(json.loads(payload))
                except json.JSONDecodeError:
                    result_holder["error"] = "invalid JSON from browser"
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(b"OK")
                done.set()
            else:
                self.send_response(404)
                self.end_headers()

        def log_message(self, *args):
            pass

    # Bind on all interfaces so the Windows host (under WSL) can reach us too.
    server = http.server.HTTPServer(("0.0.0.0", DEFAULT_PORT), Handler)
    server.timeout = 1
    try:
        _open_browser(f"http://localhost:{DEFAULT_PORT}/")
        deadline = time.time() + timeout
        while not done.is_set() and time.time() < deadline:
            server.handle_request()
    finally:
        server.server_close()

    if not done.is_set():
        raise RuntimeError("Timed out waiting for the browser WebAuthn response.")
    if "error" in result_holder:
        raise RuntimeError(f"Browser WebAuthn failed: {result_holder['error']}")
    return result_holder


def make_credential(rp_id: str, user_name: str, hint: str = "") -> dict:
    html = _render_page("create", challenge=os.urandom(32), user_name=user_name, hint=hint)
    res = _run_browser_flow(html)
    auth_data = bytes(res["authenticator_data"])
    transports = res.get("transport", []) or []
    return {
        "credential_id": list(bytes(res["credential_id"])),
        "authenticator_data": list(auth_data),
        "transport": transports[0] if transports else "unknown",
        "aaguid": _parse_aaguid(auth_data),
    }


def get_assertion(rp_id: str, credential_id, challenge, hint: str = "") -> dict:
    html = _render_page("sign", challenge=bytes(challenge), credential_id=bytes(credential_id))
    res = _run_browser_flow(html)
    client_data_json = bytes(res["client_data_json"])
    return {
        "signature": list(bytes(res["signature"])),
        "authenticator_data": list(bytes(res["authenticator_data"])),
        "client_data_hash": list(hashlib.sha256(client_data_json).digest()),
        "credential_id": list(bytes(res["credential_id"])),
    }


def _network_available(host="clients3.google.com", port=443, timeout=3) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _bluetooth_available() -> bool:
    # Best-effort: presence of a Bluetooth tool / rfkill entry suggests hybrid is usable.
    if shutil.which("bluetoothctl"):
        return True
    return os.path.isdir("/sys/class/bluetooth") and bool(os.listdir("/sys/class/bluetooth"))


def get_platform_status() -> dict:
    """Best-effort platform diagnostics, mirroring the native module's dict shape.

    On Linux we cannot query the platform authenticator directly (only the
    browser knows), so ``platform_available`` reports whether *some* browser is
    reachable to drive the flow.
    """
    has_browser = bool(
        _is_wsl()
        or shutil.which("xdg-open")
        or any(shutil.which(b) for b in
               ("google-chrome", "chromium", "chromium-browser", "firefox", "wslview"))
    )
    return {
        "api_version": 0,
        "platform_available": has_browser,
        "bluetooth_available": _bluetooth_available(),
        "network_available": _network_available(),
        "ngc_ready": has_browser,
        "ngc_error_flags": 0,
        "ngc_errors": [],
        "ngc_container": None,
    }
