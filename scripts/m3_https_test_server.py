"""Localhost-only HTTPS/TLS server for manual RCScan M3 acceptance.

The default certificate and private key are generated for this process only,
written to a temporary directory, and deleted at exit. They are test material,
not production credentials or a trusted identity.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import math
import secrets
import ssl
from contextlib import suppress
from datetime import UTC, datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory

HOST = "127.0.0.1"
HTTPS_PORT = 8443
TLS_ONLY_PORT = 9443
MAX_REQUEST_BYTES = 8_192
_PUBLIC_EXPONENT = 65_537
_SMALL_PRIMES = (3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run a localhost-only TLS server for RCScan M3 acceptance.",
    )
    parser.add_argument(
        "--mode",
        choices=("https", "tls-only"),
        default="https",
        help="HTTPS defaults to port 8443; tls-only defaults to 9443.",
    )
    parser.add_argument("--port", type=int, help="Override the mode's localhost port.")
    parser.add_argument("--certfile", type=Path, help="Optional PEM test certificate.")
    parser.add_argument("--keyfile", type=Path, help="Optional PEM test private key.")
    args = parser.parse_args()
    if (args.certfile is None) != (args.keyfile is None):
        parser.error("--certfile and --keyfile must be supplied together.")
    if args.port is not None and not 1 <= args.port <= 65_535:
        parser.error("--port must be between 1 and 65535.")
    return args


async def serve(mode: str, port: int, certfile: Path, keyfile: Path) -> None:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certfile, keyfile)
    handler = handle_https if mode == "https" else handle_tls_only
    server = await asyncio.start_server(
        handler,
        host=HOST,
        port=port,
        ssl=context,
        ssl_handshake_timeout=5.0,
    )
    print("RCScan M3 localhost-only test server")
    print(f"Mode: {mode}")
    print(f"Listening only on https://{HOST}:{port}")
    print("Certificate: ephemeral self-signed localhost test certificate")
    print("This endpoint is for authorized local testing only. Press Ctrl+C to stop.")
    async with server:
        await server.serve_forever()


async def handle_https(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
) -> None:
    try:
        request = await read_request_headers(reader)
        if not request:
            return
        request_line = request.splitlines()[0].decode("ascii", errors="replace")
        parts = request_line.split()
        if len(parts) != 3:
            await send_response(writer, "400 Bad Request", b"", include_body=False)
            return
        method, path, _version = parts
        if path != "/":
            await send_response(writer, "404 Not Found", b"Not found\n", method == "GET")
        elif method == "HEAD":
            await send_response(writer, "200 OK", b"RCScan M3 HTTPS test\n", False)
        elif method == "GET":
            await send_response(writer, "200 OK", b"RCScan M3 HTTPS test\n", True)
        else:
            await send_response(writer, "405 Method Not Allowed", b"", False)
    except asyncio.CancelledError:
        raise
    except (ConnectionError, OSError, TimeoutError):
        pass
    finally:
        await close_writer(writer)


async def handle_tls_only(
    _reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
) -> None:
    """Complete TLS, send no application data, and close."""
    await close_writer(writer)


async def read_request_headers(reader: asyncio.StreamReader) -> bytes:
    buffer = bytearray()
    try:
        async with asyncio.timeout(3.0):
            while len(buffer) <= MAX_REQUEST_BYTES:
                remaining = MAX_REQUEST_BYTES + 1 - len(buffer)
                chunk = await reader.read(min(1_024, remaining))
                if not chunk:
                    break
                buffer.extend(chunk)
                for marker in (b"\r\n\r\n", b"\n\n"):
                    position = buffer.find(marker)
                    if position >= 0:
                        return bytes(buffer[: position + len(marker)])
    except TimeoutError:
        return b""
    return b""


async def send_response(
    writer: asyncio.StreamWriter,
    status: str,
    body: bytes,
    include_body: bool,
) -> None:
    headers = (
        f"HTTP/1.1 {status}\r\n"
        "Server: RCScan-M3-Test/1.0\r\n"
        "Content-Type: text/plain; charset=utf-8\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode("ascii")
    writer.write(headers + (body if include_body else b""))
    await writer.drain()


async def close_writer(writer: asyncio.StreamWriter) -> None:
    writer.close()
    with suppress(ConnectionError, OSError):
        await writer.wait_closed()


def generate_test_certificate() -> tuple[bytes, bytes]:
    """Generate a short-lived RSA key and self-signed localhost certificate."""
    p = generate_prime(1_024)
    q = generate_prime(1_024)
    while p == q:
        q = generate_prime(1_024)
    if p < q:
        p, q = q, p
    modulus = p * q
    phi = (p - 1) * (q - 1)
    private_exponent = pow(_PUBLIC_EXPONENT, -1, phi)
    private_key = der_sequence(
        der_integer(0),
        der_integer(modulus),
        der_integer(_PUBLIC_EXPONENT),
        der_integer(private_exponent),
        der_integer(p),
        der_integer(q),
        der_integer(private_exponent % (p - 1)),
        der_integer(private_exponent % (q - 1)),
        der_integer(pow(q, -1, p)),
    )
    certificate = build_certificate(modulus, private_exponent)
    return pem("CERTIFICATE", certificate), pem("RSA PRIVATE KEY", private_key)


def build_certificate(modulus: int, private_exponent: int) -> bytes:
    signature_algorithm = der_sequence(
        der_oid("1.2.840.113549.1.1.11"),
        der_null(),
    )
    name = der_sequence(
        der_set(
            der_sequence(
                der_oid("2.5.4.3"),
                der_utf8("RCScan M3 Localhost Test"),
            )
        )
    )
    now = datetime.now(UTC)
    validity = der_sequence(
        der_utc_time(now - timedelta(days=1)),
        der_utc_time(now + timedelta(days=30)),
    )
    public_key = der_sequence(
        der_integer(modulus),
        der_integer(_PUBLIC_EXPONENT),
    )
    public_key_info = der_sequence(
        der_sequence(der_oid("1.2.840.113549.1.1.1"), der_null()),
        der_bit_string(public_key),
    )
    extensions = der_context(
        3,
        der_sequence(
            der_sequence(
                der_oid("2.5.29.19"),
                der_boolean(True),
                der_octet_string(der_sequence()),
            ),
            der_sequence(
                der_oid("2.5.29.37"),
                der_octet_string(
                    der_sequence(der_oid("1.3.6.1.5.5.7.3.1"))
                ),
            ),
            der_sequence(
                der_oid("2.5.29.17"),
                der_octet_string(
                    der_sequence(
                        der_raw(0x82, b"localhost"),
                        der_raw(0x87, bytes((127, 0, 0, 1))),
                    )
                ),
            ),
        ),
    )
    tbs_certificate = der_sequence(
        der_context(0, der_integer(2)),
        der_integer(secrets.randbits(128)),
        signature_algorithm,
        name,
        validity,
        name,
        public_key_info,
        extensions,
    )
    digest_info = bytes.fromhex("3031300d060960864801650304020105000420")
    digest_info += hashlib.sha256(tbs_certificate).digest()
    key_size = (modulus.bit_length() + 7) // 8
    padding = b"\xff" * (key_size - len(digest_info) - 3)
    encoded = b"\x00\x01" + padding + b"\x00" + digest_info
    signature = pow(int.from_bytes(encoded), private_exponent, modulus).to_bytes(
        key_size
    )
    return der_sequence(tbs_certificate, signature_algorithm, der_bit_string(signature))


def generate_prime(bits: int) -> int:
    while True:
        candidate = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if math.gcd(candidate - 1, _PUBLIC_EXPONENT) != 1:
            continue
        if any(candidate % prime == 0 for prime in _SMALL_PRIMES):
            continue
        if is_probable_prime(candidate):
            return candidate


def is_probable_prime(candidate: int, rounds: int = 24) -> bool:
    exponent = candidate - 1
    shifts = 0
    while exponent % 2 == 0:
        shifts += 1
        exponent //= 2
    for _ in range(rounds):
        base = secrets.randbelow(candidate - 3) + 2
        value = pow(base, exponent, candidate)
        if value in (1, candidate - 1):
            continue
        for _ in range(shifts - 1):
            value = pow(value, 2, candidate)
            if value == candidate - 1:
                break
        else:
            return False
    return True


def der_raw(tag: int, content: bytes) -> bytes:
    return bytes((tag,)) + der_length(len(content)) + content


def der_length(length: int) -> bytes:
    if length < 128:
        return bytes((length,))
    encoded = length.to_bytes((length.bit_length() + 7) // 8)
    return bytes((0x80 | len(encoded),)) + encoded


def der_sequence(*items: bytes) -> bytes:
    return der_raw(0x30, b"".join(items))


def der_set(*items: bytes) -> bytes:
    return der_raw(0x31, b"".join(items))


def der_integer(value: int) -> bytes:
    encoded = value.to_bytes(max(1, (value.bit_length() + 7) // 8))
    if encoded[0] & 0x80:
        encoded = b"\x00" + encoded
    return der_raw(0x02, encoded)


def der_boolean(value: bool) -> bytes:
    return der_raw(0x01, b"\xff" if value else b"\x00")


def der_null() -> bytes:
    return der_raw(0x05, b"")


def der_bit_string(value: bytes) -> bytes:
    return der_raw(0x03, b"\x00" + value)


def der_octet_string(value: bytes) -> bytes:
    return der_raw(0x04, value)


def der_utf8(value: str) -> bytes:
    return der_raw(0x0C, value.encode("utf-8"))


def der_utc_time(value: datetime) -> bytes:
    return der_raw(0x17, value.strftime("%y%m%d%H%M%SZ").encode("ascii"))


def der_context(number: int, value: bytes) -> bytes:
    return der_raw(0xA0 + number, value)


def der_oid(value: str) -> bytes:
    parts = [int(part) for part in value.split(".")]
    encoded = bytearray((40 * parts[0] + parts[1],))
    for part in parts[2:]:
        groups = [part & 0x7F]
        part >>= 7
        while part:
            groups.append(0x80 | (part & 0x7F))
            part >>= 7
        encoded.extend(reversed(groups))
    return der_raw(0x06, bytes(encoded))


def pem(label: str, value: bytes) -> bytes:
    encoded = base64.b64encode(value).decode("ascii")
    lines = "\n".join(encoded[index : index + 64] for index in range(0, len(encoded), 64))
    return f"-----BEGIN {label}-----\n{lines}\n-----END {label}-----\n".encode()


def main() -> None:
    args = parse_args()
    port = args.port or (HTTPS_PORT if args.mode == "https" else TLS_ONLY_PORT)
    if args.certfile is not None and args.keyfile is not None:
        asyncio.run(serve(args.mode, port, args.certfile, args.keyfile))
        return
    print("Generating an ephemeral localhost certificate (standard library only)...")
    certificate, private_key = generate_test_certificate()
    with TemporaryDirectory(prefix="rcscan-m3-") as directory:
        certfile = Path(directory) / "localhost-test-cert.pem"
        keyfile = Path(directory) / "localhost-test-key.pem"
        certfile.write_bytes(certificate)
        keyfile.write_bytes(private_key)
        asyncio.run(serve(args.mode, port, certfile, keyfile))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nLocal M3 test server stopped.")
