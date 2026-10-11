from http.server import ThreadingHTTPServer
from threading import Thread
from urllib.request import Request, urlopen

from collective_computation.server import HealthHandler


def run_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), HealthHandler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def test_health_endpoint_returns_json() -> None:
    server, thread = run_server()
    try:
        with urlopen(f"http://127.0.0.1:{server.server_port}/health") as response:
            assert response.status == 200
            assert response.headers["Content-Type"].startswith("application/json")
            assert b'"status": "ok"' in response.read()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_head_health_probe_returns_200_without_body() -> None:
    server, thread = run_server()
    try:
        request = Request(f"http://127.0.0.1:{server.server_port}/", method="HEAD")
        with urlopen(request) as response:
            assert response.status == 200
            assert int(response.headers["Content-Length"]) > 0
            assert response.read() == b""
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
