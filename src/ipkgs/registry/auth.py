"""Authentication and credential management."""

from __future__ import annotations

import asyncio
import os
import threading
import urllib.parse
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer

import httpx
import keyring

SERVICE_NAME = "ipkgs"
CALLBACK_PORT = 9876
CALLBACK_HOST = "localhost"

# Served at /callback — reads hash fragment and POSTs token to /token
_CALLBACK_HTML = b"""<!DOCTYPE html>
<html>
<head><title>ipkgs login</title></head>
<body>
<p>Completing login, please wait...</p>
<script>
  // Token may arrive as query param OR hash fragment (Supabase uses hash)
  function getParam(key) {
    var search = new URLSearchParams(window.location.search);
    if (search.get(key)) return search.get(key);
    var hash = new URLSearchParams(window.location.hash.slice(1));
    return hash.get(key);
  }
  var token = getParam('access_token');
  var error = getParam('error') || getParam('error_description');
  var path = token ? '/token?access_token=' + encodeURIComponent(token)
                   : '/token?error=' + encodeURIComponent(error || 'unknown');
  fetch('http://localhost:""" + str(CALLBACK_PORT).encode() + b"""' + path)
    .then(function() {
      document.body.innerHTML = '<h2>Authenticated! You can close this tab.</h2>';
    })
    .catch(function() {
      document.body.innerHTML = '<h2>Authentication failed. You can close this tab.</h2>';
    });
</script>
</body>
</html>"""


class AuthManager:
    def __init__(self, registry_url: str) -> None:
        self._registry = registry_url.rstrip("/")

    def get_token(self) -> str | None:
        """Read token from keyring, fallback to IPKGS_TOKEN env var."""
        env_token = os.environ.get("IPKGS_TOKEN")
        if env_token:
            return env_token
        return keyring.get_password(SERVICE_NAME, self._registry)

    def set_token(self, token: str) -> None:
        keyring.set_password(SERVICE_NAME, self._registry, token)

    def clear_token(self) -> None:
        try:
            keyring.delete_password(SERVICE_NAME, self._registry)
        except keyring.errors.PasswordDeleteError:
            pass

    async def login_browser(self, provider: str = "github") -> str:
        """
        Full OAuth browser login flow:
          1. Browser opens /auth/login?provider=...&cli_callback=... directly
             (server sets PKCE cookies on the browser, then redirects to Supabase)
          2. User authenticates with GitHub/Google
          3. Supabase → /auth/callback → redirects to localhost:9876/callback?access_token=
          4. POST /auth/token to exchange Supabase access_token for ipkgs_ API token
          5. Store in keyring and return token
        """
        callback_url = f"http://{CALLBACK_HOST}:{CALLBACK_PORT}/callback"

        # Step 1 — build the URL that the BROWSER will open (not a CLI HTTP call).
        # This ensures Supabase PKCE cookies are set in the browser, not our process.
        params = urllib.parse.urlencode({"provider": provider, "cli_callback": callback_url})
        auth_url = f"{self._registry}/auth/login?{params}"

        # Step 2 — start local callback server, open browser
        access_token = await _run_callback_server(auth_url, self._registry)

        # Step 4 — exchange access_token for ipkgs_ API token
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                f"{self._registry}/auth/token",
                json={"access_token": access_token},
            )
            resp.raise_for_status()
            api_token: str = resp.json()["token"]

        # Step 5 — persist
        self.set_token(api_token)
        return api_token


async def _run_callback_server(auth_url: str, registry: str = "") -> str:
    """
    Spin up a local HTTP server on localhost:9876 that handles two routes:
      GET /callback  — serves HTML that reads hash fragment and fetches /token
      GET /token     — receives the access_token extracted by the JS above
    Returns the access_token string.
    """
    received: dict[str, str] = {}
    ready = threading.Event()
    done = threading.Event()

    class _Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            parsed = urllib.parse.urlparse(self.path)
            params = urllib.parse.parse_qs(parsed.query)

            if parsed.path == "/callback":
                # Serve the HTML bridge page — JS will extract hash and call /token
                # Also handle query-param delivery directly (non-Supabase servers)
                token = params.get("access_token", [None])[0]
                if token:
                    received["access_token"] = token
                    body = b"<html><body><h2>Authenticated! You can close this tab.</h2></body></html>"
                    self._respond(200, body)
                    done.set()
                else:
                    self._respond(200, _CALLBACK_HTML)

            elif parsed.path == "/token":
                # Called by the JS bridge with the extracted token
                token = params.get("access_token", [None])[0]
                error = params.get("error", [None])[0]
                if token:
                    received["access_token"] = token
                    self._respond(200, b"OK", cors=True)
                else:
                    received["error"] = error or "unknown"
                    self._respond(400, b"Error", cors=True)
                done.set()

            else:
                self._respond(404, b"Not found")

        def _respond(self, code: int, body: bytes, cors: bool = False) -> None:
            self.send_response(code)
            content_type = b"text/html" if body.startswith(b"<") else b"text/plain"
            self.send_header("Content-Type", content_type.decode())
            self.send_header("Content-Length", str(len(body)))
            if cors:
                self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args: object) -> None:
            pass

    server = HTTPServer((CALLBACK_HOST, CALLBACK_PORT), _Handler)

    def _serve() -> None:
        ready.set()
        # Handle multiple requests (callback + token)
        while not done.is_set():
            server.handle_request()
        server.server_close()

    thread = threading.Thread(target=_serve, daemon=True)
    thread.start()
    ready.wait()

    # Step 3 — open browser
    webbrowser.open(auth_url)

    # Wait for callback (up to 120 seconds)
    await asyncio.get_event_loop().run_in_executor(
        None, lambda: done.wait(timeout=120)
    )

    if "error" in received:
        raise RuntimeError(f"OAuth error: {received['error']}")
    if "access_token" not in received:
        raise TimeoutError("Timed out waiting for browser authentication.")

    return received["access_token"]
