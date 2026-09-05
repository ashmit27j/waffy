"""Trivial demo upstream application for the docker-compose evaluation stack.

Stdlib-only (no dependencies) so its Dockerfile stays a one-liner. Its only
purpose is to give the Compose example a real backend to prove waffy is
actually proxying and inspecting traffic to -- it is a stand-in for "your
existing application," not a component of waffy itself.
"""

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class DemoHandler(BaseHTTPRequestHandler):
    def _respond(self, method: str) -> None:
        body = json.dumps(
            {
                "message": "Hello from the demo upstream application",
                "method": method,
                "path": self.path,
                "headers_received": dict(self.headers),
            }
        ).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802 -- BaseHTTPRequestHandler's naming convention
        self._respond("GET")

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(length)  # drain the body
        self._respond("POST")

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        print(f"[demo-upstream] {self.address_string()} - {format % args}")


if __name__ == "__main__":
    server = ThreadingHTTPServer(("0.0.0.0", 9000), DemoHandler)
    print("Demo upstream application listening on 0.0.0.0:9000")
    server.serve_forever()
