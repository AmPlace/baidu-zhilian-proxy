import asyncio
from contextlib import redirect_stdout
from io import StringIO
import socket
import sys
import unittest
from unittest.mock import patch

from baidu_proxy import (
    BenchmarkError,
    DEFAULT_BENCHMARK_UPLOAD_URL,
    DEFAULT_X_T5_AUTH,
    ProxyConfig,
    ProxyServer,
    benchmark_open_external_tunnel,
    benchmark_proxy_display,
    benchmark_socks_address,
    parse_args,
    print_benchmark_table,
    run_benchmark,
)


class FakeUpstream:
    def __init__(self, response_status=200):
        self.response_status = response_status
        self.requests = []
        self.payloads = []
        self.server = None

    async def start(self):
        self.server = await asyncio.start_server(self.handle, "127.0.0.1", 0)
        return self.server.sockets[0].getsockname()[1]

    async def close(self):
        self.server.close()
        await self.server.wait_closed()

    async def handle(self, reader, writer):
        try:
            header = await reader.readuntil(b"\r\n\r\n")
            self.requests.append(header)
            writer.write(
                f"HTTP/1.1 {self.response_status} Test\r\n\r\n".encode("ascii")
            )
            await writer.drain()
            if self.response_status == 200:
                data = await reader.read(4096)
                self.payloads.append(data)
                if data.startswith(b"GET "):
                    writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                else:
                    writer.write(data)
                await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()


class FakeSocket:
    def __init__(self, response=b""):
        self.response = bytearray(response)
        self.sent = []
        self.timeout = None
        self.closed = False

    def settimeout(self, timeout):
        self.timeout = timeout

    def sendall(self, data):
        self.sent.append(data)

    def recv(self, size):
        data = bytes(self.response[:size])
        del self.response[:size]
        return data

    def close(self):
        self.closed = True


class BenchmarkProxyTests(unittest.TestCase):
    def test_cli_uses_builtin_auth_value(self):
        with patch.object(sys, "argv", ["baidu_proxy.py"]):
            config = parse_args()
        self.assertEqual(config.x_t5_auth, DEFAULT_X_T5_AUTH)
        self.assertEqual(config.benchmark_upload_url, DEFAULT_BENCHMARK_UPLOAD_URL)
        self.assertTrue(config.benchmark_upload_enabled)
        self.assertEqual(config.benchmark_threads, 1)
        self.assertEqual(config.benchmark_proxy, "")
        self.assertFalse(config.benchmark_details)
        with patch.object(sys, "argv", ["baidu_proxy.py", "--no-benchmark-upload"]):
            config = parse_args()
        self.assertFalse(config.benchmark_upload_enabled)
        with patch.object(
            sys,
            "argv",
            ["baidu_proxy.py", "--benchmark-proxy", "socks5h://user:pass@127.0.0.1:1080"],
        ):
            config = parse_args()
        self.assertEqual(config.benchmark_proxy, "socks5h://user:pass@127.0.0.1:1080")

    def test_benchmark_proxy_display_hides_credentials(self):
        self.assertEqual(
            benchmark_proxy_display("http://user:secret@127.0.0.1:8080"),
            "http://127.0.0.1:8080",
        )

    def test_socks5h_uses_proxy_dns(self):
        address = benchmark_socks_address("www.baidu.com", 443, remote_dns=True)
        self.assertEqual(address[:2], b"\x03\x0d")
        self.assertEqual(address[2:-2], b"www.baidu.com")

    def test_socks5_uses_local_dns(self):
        with patch(
            "baidu_proxy.socket.getaddrinfo",
            return_value=[
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.1", 443))
            ],
        ):
            address = benchmark_socks_address("www.baidu.com", 443, remote_dns=False)
        self.assertEqual(address, b"\x01\xc0\x00\x02\x01\x01\xbb")

    def test_http_external_proxy_connect(self):
        fake = FakeSocket(b"HTTP/1.1 200 Connection established\r\n\r\n")
        config = ProxyConfig(benchmark_proxy="http://user:secret@127.0.0.1:8080")
        with patch("baidu_proxy.socket.create_connection", return_value=fake):
            self.assertIs(
                benchmark_open_external_tunnel(config, "www.baidu.com", 443), fake
            )
        request = b"".join(fake.sent)
        self.assertIn(b"CONNECT www.baidu.com:443 HTTP/1.1", request)
        self.assertIn(b"Proxy-Authorization: Basic dXNlcjpzZWNyZXQ=", request)
        self.assertFalse(fake.closed)

    def test_socks5h_external_proxy_connect(self):
        response = b"\x05\x00\x05\x00\x00\x01\x7f\x00\x00\x01\x1a\xe1"
        fake = FakeSocket(response)
        config = ProxyConfig(benchmark_proxy="socks5h://127.0.0.1:1080")
        with patch("baidu_proxy.socket.create_connection", return_value=fake):
            self.assertIs(
                benchmark_open_external_tunnel(config, "www.baidu.com", 443), fake
            )
        self.assertEqual(fake.sent[0], b"\x05\x01\x00")
        self.assertEqual(
            fake.sent[1], b"\x05\x01\x00\x03\x0dwww.baidu.com\x01\xbb"
        )
        self.assertFalse(fake.closed)

    def test_invalid_benchmark_proxy_is_rejected(self):
        with patch.object(
            sys, "argv", ["baidu_proxy.py", "--benchmark-proxy", "ftp://127.0.0.1:21"]
        ):
            with self.assertRaises(SystemExit):
                parse_args()

    def test_external_proxy_handshake_failure_closes_socket(self):
        fake = FakeSocket(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
        config = ProxyConfig(benchmark_proxy="http://127.0.0.1:8080")
        with patch("baidu_proxy.socket.create_connection", return_value=fake):
            with self.assertRaises(BenchmarkError):
                benchmark_open_external_tunnel(config, "www.baidu.com", 443)
        self.assertTrue(fake.closed)


    def test_benchmark_proxy_skips_builtin_candidates(self):
        config = ProxyConfig(
            benchmark=True,
            benchmark_proxy="socks5h://user:secret@127.0.0.1:1080",
        )
        result = {
            "ip": "custom-proxy",
            "region": "socks5h://127.0.0.1:1080",
            "errors": [],
        }
        output = StringIO()
        with patch("baidu_proxy.benchmark_candidate", return_value=result) as candidate:
            with redirect_stdout(output):
                run_benchmark(config)
        candidate.assert_called_once_with(
            ("custom-proxy", "socks5h://127.0.0.1:1080"), config
        )
        self.assertIn("socks5h://127.0.0.1:1080", output.getvalue())
        self.assertNotIn("secret", output.getvalue())

    def test_benchmark_table_hides_raw_failures(self):
        result = {
            "ip": "203.0.113.10",
            "region": "custom",
            "errors": ["download"],
            "details": ["download: upstream CONNECT returned HTTP 502"],
            "download_mbps": 1.2,
        }
        output = StringIO()
        with redirect_stdout(output):
            print_benchmark_table([result])
        rendered = output.getvalue()
        self.assertIn("失败", rendered)
        self.assertIn("汇总：成功 0，失败 1", rendered)
        self.assertNotIn("502", rendered)

    def test_partial_transfer_is_still_a_successful_result(self):
        result = {
            "ip": "203.0.113.10",
            "region": "custom",
            "errors": ["download"],
            "details": ["download: 1/4 connections failed"],
            "baidu_via_proxy_ms": 400.0,
            "download_mbps": 8.0,
            "download_bytes": 1048576,
        }
        output = StringIO()
        with redirect_stdout(output):
            print_benchmark_table([result])
        self.assertIn("成功", output.getvalue())
        self.assertIn("汇总：成功 1，失败 0", output.getvalue())

    def test_benchmark_details_are_opt_in(self):
        config = ProxyConfig(benchmark=True, benchmark_details=True)
        result = {
            "ip": "203.0.113.10",
            "region": "custom",
            "errors": ["download"],
            "details": ["download: upstream CONNECT returned HTTP 502"],
        }
        output = StringIO()
        with patch("baidu_proxy.benchmark_candidate", return_value=result):
            with redirect_stdout(output):
                run_benchmark(config)
        self.assertIn("失败详情:", output.getvalue())
        self.assertIn("HTTP 502", output.getvalue())


class ProxyTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.upstream = FakeUpstream()
        upstream_port = await self.upstream.start()
        self.proxy = ProxyServer(
            ProxyConfig(
                listen_host="127.0.0.1",
                listen_port=0,
                protocol="auto",
                upstream_host="cloudnproxy.baidu.com",
                upstream_port=upstream_port,
                upstream_ips=("127.0.0.1",),
                x_t5_auth="test-auth",
            )
        )
        await self.proxy.start()
        self.proxy_port = self.proxy.server.sockets[0].getsockname()[1]

    async def asyncTearDown(self):
        await self.proxy.close()
        await self.upstream.close()

    async def test_http_connect_is_tunneled(self):
        reader, writer = await asyncio.open_connection("127.0.0.1", self.proxy_port)
        writer.write(b"CONNECT example.com:80 HTTP/1.1\r\nHost: example.com\r\n\r\n")
        await writer.drain()
        self.assertTrue((await reader.readuntil(b"\r\n\r\n")).startswith(b"HTTP/1.1 200"))
        writer.write(b"hello")
        await writer.drain()
        self.assertEqual(await reader.readexactly(5), b"hello")
        writer.close()
        await writer.wait_closed()
        self.assertIn(b"CONNECT example.com:80", self.upstream.requests[0])
        self.assertIn(b"X-T5-Auth: test-auth", self.upstream.requests[0])

    async def test_socks5_domain_is_tunneled(self):
        reader, writer = await asyncio.open_connection("127.0.0.1", self.proxy_port)
        writer.write(b"\x05\x01\x00")
        await writer.drain()
        self.assertEqual(await reader.readexactly(2), b"\x05\x00")
        writer.write(b"\x05\x01\x00\x03\x0bexample.com\x00\x50")
        await writer.drain()
        self.assertEqual((await reader.readexactly(10))[1], 0)
        writer.write(b"world")
        await writer.drain()
        self.assertEqual(await reader.readexactly(5), b"world")
        writer.close()
        await writer.wait_closed()
        self.assertIn(b"CONNECT example.com:80", self.upstream.requests[0])

    async def test_http_absolute_form_is_rewritten(self):
        reader, writer = await asyncio.open_connection("127.0.0.1", self.proxy_port)
        writer.write(
            b"GET http://example.com/path?q=1 HTTP/1.1\r\n"
            b"Host: example.com\r\nProxy-Connection: keep-alive\r\n\r\n"
        )
        await writer.drain()
        response = await reader.readuntil(b"\r\n\r\n")
        self.assertTrue(response.startswith(b"HTTP/1.1 200"))
        self.assertEqual(await reader.readexactly(2), b"ok")
        self.assertIn(b"CONNECT example.com:80", self.upstream.requests[0])
        self.assertIn(b"GET /path?q=1 HTTP/1.1", self.upstream.payloads[0])
        self.assertNotIn(b"Proxy-Connection:", self.upstream.payloads[0])
        writer.close()
        await writer.wait_closed()

    async def test_upstream_rejection_returns_http_error(self):
        await self.proxy.close()
        await self.upstream.close()
        self.upstream = FakeUpstream(response_status=403)
        upstream_port = await self.upstream.start()
        self.proxy = ProxyServer(
            ProxyConfig(
                listen_port=0,
                upstream_host="127.0.0.1",
                upstream_port=upstream_port,
                upstream_ips=("127.0.0.1",),
                x_t5_auth="test-auth",
            )
        )
        await self.proxy.start()
        proxy_port = self.proxy.server.sockets[0].getsockname()[1]
        reader, writer = await asyncio.open_connection("127.0.0.1", proxy_port)
        writer.write(b"CONNECT example.com:80 HTTP/1.1\r\n\r\n")
        await writer.drain()
        self.assertTrue((await reader.readuntil(b"\r\n\r\n")).startswith(b"HTTP/1.1 400"))
        writer.close()
        await writer.wait_closed()


if __name__ == "__main__":
    unittest.main()
