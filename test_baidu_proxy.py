import asyncio
import unittest

from baidu_proxy import ProxyConfig, ProxyServer


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
