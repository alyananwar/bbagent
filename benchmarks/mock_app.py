"""A tiny intentionally-broken app for benchmarking research depth, not scanner count.

It has NOTHING a template scanner flags: no known CVE, no default creds, no stack
trace, no exposed .git. What it does have is one authorization bug that only shows
up when you compare two identities:

  GET /api/v2/orders/<id>   requires a token, but never checks who owns the order
  GET /admin/users/<id>     correctly refuses non-admin tokens (a true negative)
  GET /health               public, boring (must not be reported)

Run standalone:  python3 benchmarks/mock_app.py 8099
Local only. Binds 127.0.0.1.
"""
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TOKEN_A = "token-alice"
TOKEN_B = "token-bob"
ADMIN_TOKEN = "token-root"

ORDERS = {
    "1042": {"id": 1042, "owner_id": "alice", "total": 89.99, "items": ["kettle"]},
    "1043": {"id": 1043, "owner_id": "bob", "total": 12.50, "items": ["mug"]},
}
USERS = {"7": {"id": 7, "email": "alice@example.test", "role": "user"}}

INDEX = ("<html><body><a href='/api/v2/orders/1042'>order</a>"
         "<a href='/admin/users/7'>admin</a><a href='/health'>health</a></body></html>")


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):      # keep benchmark output readable
        pass

    def _send(self, code, body, ctype="application/json"):
        raw = body.encode() if isinstance(body, str) else body
        try:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
        except (BrokenPipeError, ConnectionResetError):
            pass          # scanners hang up mid-response constantly; not an error

    def do_GET(self):                        # noqa: N802 - stdlib naming
        token = (self.headers.get("Authorization") or "").strip()
        path = self.path.split("?")[0]

        if path == "/":
            return self._send(200, INDEX, "text/html")
        if path == "/health":
            return self._send(200, json.dumps({"status": "ok"}))

        if path.startswith("/api/v2/orders/"):
            oid = path.rsplit("/", 1)[-1]
            if token not in (TOKEN_A, TOKEN_B, ADMIN_TOKEN):
                return self._send(401, json.dumps({"error": "unauthenticated"}))
            order = ORDERS.get(oid)
            if order is None:
                return self._send(404, json.dumps({"error": "not found"}))
            # THE BUG: authenticated is treated as authorized. No ownership check.
            return self._send(200, json.dumps(order))

        if path.startswith("/admin/users/"):
            if token != ADMIN_TOKEN:
                return self._send(403, json.dumps({"error": "forbidden"}))
            return self._send(200, json.dumps(USERS.get(path.rsplit("/", 1)[-1], {})))

        return self._send(404, json.dumps({"error": "not found"}))


class _QuietServer(ThreadingHTTPServer):
    """Scanners reset connections constantly; those are not server errors."""

    def handle_error(self, request, client_address):
        import sys as _sys
        exc = _sys.exc_info()[0]
        if exc in (BrokenPipeError, ConnectionResetError):
            return
        ThreadingHTTPServer.handle_error(self, request, client_address)


def serve(port=0):
    """Start in a daemon thread. Returns (server, port)."""
    # threading matters: a crawler opens several connections at once and a
    # single-threaded server just deadlocks it
    srv = _QuietServer(("127.0.0.1", port), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8099
    srv, port = serve(port)
    print("mock app on http://127.0.0.1:%d/  tokens: %s (alice), %s (bob), %s (admin)"
          % (port, TOKEN_A, TOKEN_B, ADMIN_TOKEN))
    try:
        while True:
            import time
            time.sleep(1)
    except KeyboardInterrupt:
        srv.shutdown()
