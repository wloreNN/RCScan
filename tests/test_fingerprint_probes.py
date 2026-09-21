import asyncio
import ssl
from unittest.mock import AsyncMock, MagicMock

import pytest

from rcscan import __version__
from rcscan.fingerprint.probes import ProbeClient


class BufferedReader:
    def __init__(self, data: bytes) -> None:
        self._data = data

    async def read(self, size: int) -> bytes:
        chunk, self._data = self._data[:size], self._data[size:]
        return chunk


def reader_with(data: bytes) -> BufferedReader:
    return BufferedReader(data)


def writer_mock() -> MagicMock:
    writer = MagicMock()
    writer.drain = AsyncMock()
    writer.wait_closed = AsyncMock()
    return writer


def client(
    connector,
    *,
    tls_connector=None,
    timeout: float = 0.05,
    banner_limit: int = 8,
    header_limit: int = 64,
) -> ProbeClient:
    return ProbeClient(
        timeout_seconds=timeout,
        max_banner_bytes=banner_limit,
        max_header_bytes=header_limit,
        plain_connector=connector,
        tls_connector=tls_connector,
    )


def test_passive_banner_reads_one_extra_byte_and_returns_bounded_data() -> None:
    writer = writer_mock()
    connector = AsyncMock(return_value=(reader_with(b"123456789more"), writer))

    result = asyncio.run(client(connector).passive_banner("10.0.0.1", 2222))

    assert result.data == b"12345678"
    assert result.truncated is True
    connector.assert_awaited_once_with("10.0.0.1", 2222)
    writer.close.assert_called_once_with()
    writer.wait_closed.assert_awaited_once_with()


def test_passive_banner_immediate_close_is_empty_success() -> None:
    writer = writer_mock()
    connector = AsyncMock(return_value=(reader_with(b""), writer))

    result = asyncio.run(client(connector).passive_banner("10.0.0.1", 22))

    assert result.data == b""
    assert result.error is None
    assert result.truncated is False


def test_passive_banner_timeout_is_sanitized_and_writer_is_closed() -> None:
    async def never_returns(_size: int) -> bytes:
        await asyncio.sleep(60)
        return b""

    reader = MagicMock()
    reader.read = AsyncMock(side_effect=never_returns)
    writer = writer_mock()
    connector = AsyncMock(return_value=(reader, writer))

    result = asyncio.run(
        client(connector, timeout=0.001).passive_banner("10.0.0.1", 22)
    )

    assert result.data == b""
    assert result.error == "TimeoutError"
    writer.close.assert_called_once_with()
    writer.wait_closed.assert_awaited_once_with()


def test_http_writes_exact_head_request_and_stops_at_crlf_boundary() -> None:
    writer = writer_mock()
    response = b"HTTP/1.1 200 OK\r\nServer: unit\r\n\r\nignored body"
    connector = AsyncMock(return_value=(reader_with(response), writer))

    result = asyncio.run(
        client(connector).http(
            "10.0.0.1",
            8080,
            method="HEAD",
            host_header="example.internal",
            use_tls=False,
            server_hostname=None,
        )
    )

    assert result.data == b"HTTP/1.1 200 OK\r\nServer: unit\r\n\r\n"
    writer.write.assert_called_once_with(
        (
            "HEAD / HTTP/1.1\r\n"
            "Host: example.internal\r\n"
            f"User-Agent: RCScan/{__version__}\r\n"
            "Connection: close\r\n\r\n"
        ).encode("ascii")
    )
    writer.drain.assert_awaited_once_with()


def test_http_sanitizes_host_header_and_bounds_missing_header_boundary() -> None:
    writer = writer_mock()
    connector = AsyncMock(return_value=(reader_with(b"A" * 100), writer))

    result = asyncio.run(
        client(connector, header_limit=16).http(
            "10.0.0.1",
            80,
            method="GET",
            host_header="safe\r\nInjected: yes",
            use_tls=False,
            server_hostname=None,
        )
    )

    assert result.data == b"A" * 16
    assert result.truncated is True
    request = writer.write.call_args.args[0]
    assert b"Host: safeInjected: yes\r\n" in request
    assert request.count(b"\r\n") == 5


def test_http_accepts_lf_header_boundary_without_reading_body() -> None:
    writer = writer_mock()
    connector = AsyncMock(
        return_value=(reader_with(b"HTTP/1.0 200 OK\nServer: test\n\nbody"), writer)
    )

    result = asyncio.run(
        client(connector).http(
            "10.0.0.1",
            80,
            method="HEAD",
            host_header="10.0.0.1",
            use_tls=False,
            server_hostname=None,
        )
    )

    assert result.data.endswith(b"\n\n")
    assert b"body" not in result.data
    assert result.truncated is False


def test_tls_probe_uses_explicit_inspection_context_and_extracts_metadata() -> None:
    writer = writer_mock()
    ssl_object = MagicMock()
    ssl_object.version.return_value = "TLSv1.3"
    ssl_object.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
    ssl_object.getpeercert.return_value = {
        "serialNumber": "01",
        "subject": ((("commonName", "unit.test"),),),
    }
    writer.get_extra_info.return_value = ssl_object
    tls_connector = AsyncMock(return_value=(reader_with(b""), writer))
    plain_connector = AsyncMock(side_effect=AssertionError("plain connector used"))

    result = asyncio.run(
        client(plain_connector, tls_connector=tls_connector).tls(
            "10.0.0.1", 443, server_hostname="unit.test"
        )
    )

    assert result.succeeded is True
    assert result.version == "TLSv1.3"
    assert result.cipher == "TLS_AES_256_GCM_SHA384"
    assert result.certificate is not None
    assert result.certificate["serialNumber"] == "01"
    kwargs = tls_connector.await_args.kwargs
    assert isinstance(kwargs["ssl"], ssl.SSLContext)
    assert kwargs["ssl"].check_hostname is False
    assert kwargs["ssl"].verify_mode is ssl.CERT_NONE
    assert kwargs["server_hostname"] == "unit.test"
    assert kwargs["ssl_handshake_timeout"] == 0.05
    plain_connector.assert_not_awaited()


def test_https_request_uses_tls_connector_and_closes_writer() -> None:
    writer = writer_mock()
    tls_connector = AsyncMock(
        return_value=(reader_with(b"HTTP/1.1 200 OK\r\n\r\n"), writer)
    )
    plain_connector = AsyncMock(side_effect=AssertionError("plain connector used"))

    result = asyncio.run(
        client(plain_connector, tls_connector=tls_connector).http(
            "10.0.0.1",
            9443,
            method="HEAD",
            host_header="unit.test",
            use_tls=True,
            server_hostname="unit.test",
        )
    )

    assert result.data == b"HTTP/1.1 200 OK\r\n\r\n"
    tls_connector.assert_awaited_once()
    plain_connector.assert_not_awaited()
    writer.close.assert_called_once_with()
    writer.wait_closed.assert_awaited_once_with()


def test_probe_cancellation_propagates_after_writer_close_and_wait_closed() -> None:
    async def exercise() -> MagicMock:
        writer = writer_mock()
        reader = MagicMock()
        reader.read = AsyncMock(side_effect=asyncio.CancelledError)
        connector = AsyncMock(return_value=(reader, writer))
        with pytest.raises(asyncio.CancelledError):
            await client(connector).passive_banner("10.0.0.1", 22)
        return writer

    writer = asyncio.run(exercise())

    writer.close.assert_called_once_with()
    writer.wait_closed.assert_awaited_once_with()
