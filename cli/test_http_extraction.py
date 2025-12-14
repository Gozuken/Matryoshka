from core import circuit_builder


def _run():
    # Simple test: extract body from a basic HTTP response
    resp = b"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: 13\r\n\r\nHello, world!"
    assert resp.startswith(b"HTTP/")
    header, body = resp.split(b"\r\n\r\n", 1)
    assert body.decode('utf-8') == "Hello, world!"

    # Test empty body
    resp = b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n"
    header, body = resp.split(b"\r\n\r\n", 1)
    assert body == b""

    # Non-HTTP response case
    resp = b"SOME PROTOCOL RESPONSE\nOK\n"
    assert not resp.startswith(b"HTTP/")


if __name__ == "__main__":
    _run()
    print('All tests passed')
