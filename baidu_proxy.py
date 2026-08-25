#!/usr/bin/env python3
"""Local HTTP/SOCKS5 proxy backed by the Baidu CONNECT proxy.

The upstream protocol matches lua/backend-baidu.lua: connect to the configured
endpoint and send an HTTP CONNECT request containing the requested destination.
"""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import logging
import os
import re
import ssl
from dataclasses import dataclass
from typing import Optional, Tuple
from urllib.parse import urlsplit


LOG = logging.getLogger("baidu-proxy")
DEFAULT_UPSTREAM_HOST = "cloudnproxy.baidu.com"
DEFAULT_UPSTREAM_PORT = 443
DEFAULT_LISTEN_PORT = 26970
# Matches the X-T5-Auth value from the supplied Lua backend.
DEFAULT_X_T5_AUTH = "1951164069"
DEFAULT_USER_AGENT = (
    "okhttp/3.11.0 SP-engine/2.71.0 "
    "Dalvik/2.1.0 (Linux; U; Android 9; HMA-AL00 Build/PQ3B.190801.002) "
    "baiduboxapp/13.33.0.11 (Baidu; P1 9)"
)
MAX_HTTP_HEADER = 64 * 1024
HTTP_REQUEST_LINE = re.compile(r"^([!#$%&'*+.^_`|~0-9A-Za-z-]+)\s+(\S+)\s+HTTP/(1\.[01])$")


class ProxyError(Exception):
    """An expected proxy-level failure that can be sent to the client."""


class UpstreamHandshakeError(ProxyError):
    pass


@dataclass(frozen=True)
class ProxyConfig:
    listen_host: str = "127.0.0.1"
    listen_port: int = DEFAULT_LISTEN_PORT
    protocol: str = "auto"
    upstream_host: str = DEFAULT_UPSTREAM_HOST
    upstream_port: int = DEFAULT_UPSTREAM_PORT
    upstream_ips: Tuple[str, ...] = ()
    x_t5_auth: str = ""
    connect_timeout: float = 15.0
    upstream_tls: bool = False


def format_authority(host: str, port: int) -> str:
    """Format a host:port authority, including brackets for IPv6."""

    if ":" in host and not host.startswith("["):
        return f"[{host}]:{port}"
    return f"{host}:{port}"


def parse_host_port(value: str, default_port: Optional[int] = None) -> Tuple[str, int]:
    """Parse domain, IPv4, bracketed IPv6, or host:port authority."""

    value = value.strip()
    if not value or "\r" in value or "\n" in value:
        raise ProxyError("invalid destination")

    if value.startswith("["):
        closing = value.find("]")
        if closing < 0:
            raise ProxyError("invalid IPv6 destination")
        host = value[1:closing]
        suffix = value[closing + 1 :]
        if suffix:
            if not suffix.startswith(":"):
                raise ProxyError("invalid destination port")
            port_text = suffix[1:]
        elif default_port is not None:
            port_text = str(default_port)
        else:
            raise ProxyError("destination port is required")
    elif value.count(":") == 1:
        host, port_text = value.rsplit(":", 1)
    elif value.count(":") > 1:
        # SOCKS5 carries the address type separately, but accepting an
        # unbracketed IPv6 literal here is useful for HTTP Host headers.
        host = value
        if default_port is None:
            raise ProxyError("destination port is required")
        port_text = str(default_port)
    else:
        host = value
        if default_port is None:
            raise ProxyError("destination port is required")
        port_text = str(default_port)

    if not host or not port_text.isdigit():
        raise ProxyError("invalid destination")
    port = int(port_text)
    if not 1 <= port <= 65535:
        raise ProxyError("destination port is out of range")
    return host, port


def _header_lines(header: bytes) -> list[str]:
    try:
        text = header.decode("iso-8859-1")
    except UnicodeDecodeError as exc:
        raise ProxyError("invalid HTTP header") from exc
    if not text.endswith("\r\n\r\n"):
        raise ProxyError("incomplete HTTP header")
    return text[:-4].split("\r\n")


async def read_header(reader: asyncio.StreamReader) -> bytes:
    try:
        return await reader.readuntil(b"\r\n\r\n")
    except (asyncio.LimitOverrunError, asyncio.IncompleteReadError) as exc:
        raise ProxyError("HTTP header is missing or too large") from exc


async def open_upstream(
    config: ProxyConfig, target_host: str, target_port: int
) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """Open and authenticate one upstream tunnel for a destination."""

    ssl_context = None
    server_hostname = None
    if config.upstream_tls:
        ssl_context = ssl.create_default_context()
        server_hostname = config.upstream_host

    request = (
        f"CONNECT {format_authority(target_host, target_port)} HTTP/1.1\r\n"
        "Host: ascdn.baidu.com\r\n"
        "Proxy-Connection: Keep-Alive\r\n"
        f"X-T5-Auth: {config.x_t5_auth}\r\n"
        f"User-Agent: {DEFAULT_USER_AGENT}\r\n"
        "\r\n"
    ).encode("ascii")
    endpoints = config.upstream_ips or (config.upstream_host,)
    failures = []

    for endpoint in endpoints:
        writer = None
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    endpoint,
                    config.upstream_port,
                    ssl=ssl_context,
                    server_hostname=server_hostname,
                ),
                timeout=config.connect_timeout,
            )
            writer.write(request)
            await asyncio.wait_for(writer.drain(), timeout=config.connect_timeout)
            response = await asyncio.wait_for(read_header(reader), timeout=config.connect_timeout)
            lines = _header_lines(response)
            status_line = lines[0] if lines else ""
            match = re.match(r"^HTTP/\d\.\d\s+(\d{3})(?:\s|$)", status_line)
            if not match:
                raise UpstreamHandshakeError("upstream returned an invalid HTTP response")
            status = int(match.group(1))
            if not 200 <= status < 300:
                raise UpstreamHandshakeError(f"upstream CONNECT rejected with HTTP {status}")
            return reader, writer
        except (OSError, UnicodeError, asyncio.TimeoutError, ProxyError) as exc:
            failures.append(f"{endpoint}: {exc}")
            if writer is not None:
                writer.close()
                try:
                    await writer.wait_closed()
                except OSError:
                    pass

    raise UpstreamHandshakeError("all upstream endpoints failed: " + "; ".join(failures))


async def relay(
    left_reader: asyncio.StreamReader,
    left_writer: asyncio.StreamWriter,
    right_reader: asyncio.StreamReader,
    right_writer: asyncio.StreamWriter,
) -> None:
    async def copy_stream(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            while True:
                data = await reader.read(64 * 1024)
                if not data:
                    break
                writer.write(data)
                await writer.drain()
        except (ConnectionError, asyncio.IncompleteReadError, OSError):
            pass
        finally:
            try:
                writer.write_eof()
                await writer.drain()
            except (AttributeError, ConnectionError, OSError, RuntimeError):
                pass

    await asyncio.gather(
        copy_stream(left_reader, right_writer),
        copy_stream(right_reader, left_writer),
        return_exceptions=True,
    )


def http_response(status: int, reason: str, body: str = "") -> bytes:
    payload = body.encode("utf-8")
    return (
        f"HTTP/1.1 {status} {reason}\r\n"
        "Connection: close\r\n"
        f"Content-Length: {len(payload)}\r\n"
        "Content-Type: text/plain; charset=utf-8\r\n"
        "\r\n"
    ).encode("ascii") + payload


class ProxyServer:
    def __init__(self, config: ProxyConfig):
        self.config = config
        self.server: Optional[asyncio.AbstractServer] = None

    async def start(self) -> None:
        self.server = await asyncio.start_server(
            self.handle_client,
            self.config.listen_host,
            self.config.listen_port,
            limit=MAX_HTTP_HEADER,
        )

    async def close(self) -> None:
        if self.server is not None:
            self.server.close()
            await self.server.wait_closed()

    async def handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        peer = writer.get_extra_info("peername")
        try:
            first = await asyncio.wait_for(reader.readexactly(1), timeout=self.config.connect_timeout)
            if self.config.protocol == "socks5" or (
                self.config.protocol == "auto" and first == b"\x05"
            ):
                await self.handle_socks5(first, reader, writer)
            elif self.config.protocol == "http" or self.config.protocol == "auto":
                await self.handle_http(first, reader, writer)
            else:
                raise ProxyError("unsupported local protocol")
        except (ConnectionError, asyncio.IncompleteReadError, asyncio.TimeoutError):
            pass
        except ProxyError as exc:
            LOG.info("client %s closed with proxy error: %s", peer, exc)
            if not writer.is_closing():
                writer.write(http_response(400, "Bad Request", str(exc)))
                await writer.drain()
        except Exception:
            LOG.exception("unexpected client error from %s", peer)
        finally:
            if not writer.is_closing():
                writer.close()
            await writer.wait_closed()

    async def handle_http(
        self,
        first: bytes,
        reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
    ) -> None:
        header = first + await read_header(reader)
        lines = _header_lines(header)
        if not lines:
            raise ProxyError("empty HTTP request")
        match = HTTP_REQUEST_LINE.match(lines[0])
        if not match:
            raise ProxyError("invalid HTTP request line")
        method, request_target, version = match.groups()
        headers = self.parse_headers(lines[1:])

        if method.upper() == "CONNECT":
            target_host, target_port = parse_host_port(request_target, 443)
            upstream_reader, upstream_writer = await open_upstream(
                self.config, target_host, target_port
            )
            client_writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await client_writer.drain()
            await relay(reader, client_writer, upstream_reader, upstream_writer)
            upstream_writer.close()
            await upstream_writer.wait_closed()
            return

        target_host, target_port, origin_target = self.http_destination(
            request_target, headers
        )
        upstream_reader, upstream_writer = await open_upstream(
            self.config, target_host, target_port
        )
        forwarded_header = self.forward_http_header(
            method, origin_target, version, lines[1:], target_host, target_port
        )
        upstream_writer.write(forwarded_header)
        await upstream_writer.drain()
        await relay(reader, client_writer, upstream_reader, upstream_writer)
        upstream_writer.close()
        await upstream_writer.wait_closed()

    @staticmethod
    def parse_headers(lines: list[str]) -> dict[str, str]:
        headers: dict[str, str] = {}
        for line in lines:
            if ":" not in line:
                raise ProxyError("invalid HTTP header line")
            name, value = line.split(":", 1)
            if not name or "\r" in name or "\n" in name:
                raise ProxyError("invalid HTTP header name")
            headers[name.lower()] = value.strip()
        return headers

    @staticmethod
    def http_destination(
        request_target: str, headers: dict[str, str]
    ) -> Tuple[str, int, str]:
        parsed = urlsplit(request_target)
        if parsed.scheme and parsed.netloc:
            if parsed.scheme.lower() not in {"http", "https"}:
                raise ProxyError("unsupported URL scheme")
            host = parsed.hostname
            if not host:
                raise ProxyError("URL has no host")
            port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
            origin = parsed.path or "/"
            if parsed.query:
                origin += "?" + parsed.query
            return host, port, origin

        host_header = headers.get("host")
        if not host_header:
            raise ProxyError("HTTP request needs an absolute URL or Host header")
        host, port = parse_host_port(host_header, 80)
        if not request_target.startswith("/"):
            raise ProxyError("invalid origin-form request target")
        return host, port, request_target

    @staticmethod
    def forward_http_header(
        method: str,
        origin_target: str,
        version: str,
        raw_header_lines: list[str],
        target_host: str,
        target_port: int,
    ) -> bytes:
        output = [f"{method} {origin_target} HTTP/{version}"]
        saw_host = False
        for line in raw_header_lines:
            name, value = line.split(":", 1)
            lower_name = name.lower()
            if lower_name in {"proxy-connection", "proxy-authorization"}:
                continue
            if lower_name == "host":
                saw_host = True
            output.append(f"{name}:{value}")
        if not saw_host:
            output.append(f"Host: {format_authority(target_host, target_port)}")
        return ("\r\n".join(output) + "\r\n\r\n").encode("iso-8859-1")

    async def handle_socks5(
        self,
        first: bytes,
        reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
    ) -> None:
        nmethods = (await reader.readexactly(1))[0]
        methods = await reader.readexactly(nmethods)
        if 0x00 not in methods:
            client_writer.write(b"\x05\xff")
            await client_writer.drain()
            return
        client_writer.write(b"\x05\x00")
        await client_writer.drain()

        version, command, _, address_type = await reader.readexactly(4)
        if version != 5:
            client_writer.write(self.socks_reply(0x01))
            await client_writer.drain()
            return
        if command != 1:
            client_writer.write(self.socks_reply(0x07))
            await client_writer.drain()
            return

        try:
            target_host, target_port = await self.read_socks_target(reader, address_type)
        except ProxyError:
            client_writer.write(self.socks_reply(0x08))
            await client_writer.drain()
            return
        try:
            upstream_reader, upstream_writer = await open_upstream(
                self.config, target_host, target_port
            )
        except ProxyError:
            client_writer.write(self.socks_reply(0x01))
            await client_writer.drain()
            return

        client_writer.write(self.socks_reply(0x00))
        await client_writer.drain()
        await relay(reader, client_writer, upstream_reader, upstream_writer)
        upstream_writer.close()
        await upstream_writer.wait_closed()

    @staticmethod
    async def read_socks_target(
        reader: asyncio.StreamReader, address_type: int
    ) -> Tuple[str, int]:
        if address_type == 1:
            host = ".".join(str(part) for part in await reader.readexactly(4))
        elif address_type == 3:
            length = (await reader.readexactly(1))[0]
            if not length:
                raise ProxyError("empty SOCKS5 domain")
            host = (await reader.readexactly(length)).decode("idna")
        elif address_type == 4:
            raw = await reader.readexactly(16)
            groups = [raw[index : index + 2].hex() for index in range(0, 16, 2)]
            host = ":".join(groups)
        else:
            raise ProxyError("unsupported SOCKS5 address type")
        port = int.from_bytes(await reader.readexactly(2), "big")
        if port == 0:
            raise ProxyError("invalid SOCKS5 destination port")
        return host, port

    @staticmethod
    def socks_reply(code: int) -> bytes:
        return b"\x05" + bytes([code, 0, 1]) + b"\x00\x00\x00\x00\x00\x00"


def parse_args() -> ProxyConfig:
    parser = argparse.ArgumentParser(
        description="Expose a local HTTP/SOCKS5 proxy through the Baidu CONNECT endpoint."
    )
    parser.add_argument("--listen-host", default="127.0.0.1")
    parser.add_argument("--listen-port", type=int, default=DEFAULT_LISTEN_PORT)
    parser.add_argument("--protocol", choices=("auto", "http", "socks5"), default="auto")
    parser.add_argument("--upstream-host", default=DEFAULT_UPSTREAM_HOST)
    parser.add_argument("--upstream-port", type=int, default=DEFAULT_UPSTREAM_PORT)
    parser.add_argument(
        "--upstream-ip",
        dest="upstream_ips",
        action="append",
        default=[],
        metavar="IP",
        help="connect to this cloudnproxy IP instead of DNS; repeat for ordered failover",
    )
    parser.add_argument(
        "--x-t5-auth",
        default=os.environ.get("BAIDU_X_T5_AUTH", DEFAULT_X_T5_AUTH),
        help="X-T5-Auth value; overrides the built-in Lua value",
    )
    parser.add_argument("--connect-timeout", type=float, default=15.0)
    parser.add_argument(
        "--upstream-tls",
        action="store_true",
        help="wrap the TCP connection to the upstream in TLS (off by default to match the Lua script)",
    )
    args = parser.parse_args()
    for endpoint in args.upstream_ips:
        try:
            ipaddress.ip_address(endpoint)
        except ValueError:
            parser.error(f"--upstream-ip is not a valid IP address: {endpoint}")
    args.upstream_ips = tuple(args.upstream_ips)
    return ProxyConfig(**vars(args))


async def run(config: ProxyConfig) -> None:
    proxy = ProxyServer(config)
    await proxy.start()
    LOG.info(
        "listening on %s:%d (%s), upstream %s:%d%s",
        config.listen_host,
        config.listen_port,
        config.protocol,
        ",".join(config.upstream_ips) if config.upstream_ips else config.upstream_host,
        config.upstream_port,
        " with TLS" if config.upstream_tls else "",
    )
    try:
        await asyncio.Event().wait()
    finally:
        await proxy.close()


def main() -> None:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    try:
        asyncio.run(run(parse_args()))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
