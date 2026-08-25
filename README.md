# Baidu CONNECT local proxy

This program exposes one local port that accepts either a normal HTTP proxy
request or SOCKS5. For each destination it opens a separate connection to
`cloudnproxy.baidu.com:443`, sends the HTTP CONNECT handshake used by the
provided Lua backend, then relays bytes in both directions.

The default upstream connection is plain TCP, even though the port is 443. That
matches the Lua script and the observed `HTTP/1.1 200 Connection established`
response. Use `--upstream-tls` only when your upstream deployment explicitly
requires TLS.

## Run

The `X-T5-Auth` value from the supplied Lua script is built into the program.
No environment variable is required. You can still override it when needed:

```sh
python3 baidu_proxy.py --listen-host 127.0.0.1 --listen-port 26970
# optional override
BAIDU_X_T5_AUTH='replacement-value' python3 baidu_proxy.py --listen-port 26970
```

The local port auto-detects both protocols:

```sh
# HTTP proxy, including HTTPS CONNECT
curl -x http://127.0.0.1:26970 http://example.com/
curl -x http://127.0.0.1:26970 https://example.com/

# SOCKS5 with remote DNS resolution
curl --proxy socks5h://127.0.0.1:26970 https://example.com/
```

To force a specific BGP address and bypass DNS, add `--upstream-ip`:

```sh
python3 baidu_proxy.py --listen-port 26970 --upstream-ip 203.0.113.10
```

You can provide it more than once. Addresses are tried in the order given when
the proxy opens a tunnel:

```sh
python3 baidu_proxy.py \
  --listen-port 26970 \
  --upstream-ip 203.0.113.10 \
  --upstream-ip 203.0.113.11
```

The IP is only used for the TCP connection. The logical upstream hostname and
the Lua-compatible CONNECT headers remain unchanged. IPv4 and IPv6 addresses
are accepted.

## Benchmark

Run the built-in concurrent link benchmark:

```sh
python3 baidu_proxy.py --benchmark
```

For each built-in IP it reports:

- TCP connect latency to the IP on port 443;
- direct TCP connect latency to `www.baidu.com:443`;
- latency to establish `www.baidu.com:443` through that cloudnproxy IP;
- download throughput through that cloudnproxy IP using the Ctyun URL.

The download test reads at most 2 MiB by default and discards the bytes in
memory. It does not create a download file. Tests run concurrently; reduce the
traffic or test only selected IPs like this:

```sh
python3 baidu_proxy.py \
  --benchmark \
  --upstream-ip 36.155.169.188 \
  --upstream-ip 183.240.98.84 \
  --benchmark-bytes 1048576
```

Use `--benchmark-url URL` to replace the download target, and
`--benchmark-timeout SECONDS` to bound each connection, tunnel, or read
operation. The result table is printed to stdout only. By default each row
shows only `成功` or `失败`; individual HTTP 502/503/522 responses are not
printed. Add `--benchmark-details` when diagnosing a failed run.

The table reports the TCP latency, direct Baidu latency, proxy connection
latency, download speed, upload speed, and an overall result. A multi-thread
row is marked `成功` when the proxy connection succeeds and at least one
direction transfers bytes. A few failed parallel connections do not hide a
valid speed result; use `--benchmark-details` to inspect those partial failures.

Use `--benchmark-threads N` for N simultaneous transfer connections per IP.
This is separate from `--benchmark-workers`, which controls how many different
IPs are tested at the same time. The default is one transfer connection per IP:

```sh
python3 baidu_proxy.py \
  --benchmark \
  --upstream-ip 180.101.50.208 \
  --benchmark-workers 1 \
  --benchmark-threads 4 \
  --benchmark-bytes 8388608 \
  --benchmark-upload-bytes 8388608
```

The byte limits apply per transfer connection, so four threads can transfer up
to four times the configured bytes. Keeping `--benchmark-workers 1` makes a
single-IP multi-thread result easier to compare.

To benchmark through an existing local HTTP or SOCKS5 proxy instead of the
built-in cloudnproxy path, pass `--benchmark-proxy`. When set, the built-in IP
list is skipped and one result is produced for that proxy:

```sh
python3 baidu_proxy.py \
  --benchmark \
  --benchmark-proxy socks5h://127.0.0.1:1080 \
  --benchmark-workers 1 \
  --benchmark-threads 4
```

HTTP CONNECT proxies use `http://host:port`; SOCKS5 proxies use
`socks5://host:port` or `socks5h://host:port`. Optional
`user:password@` credentials are supported. `socks5` resolves benchmark
hostnames locally; `socks5h` keeps target DNS at the SOCKS5 proxy.
In this mode, `ip_tcp_ms` is the TCP latency to the external proxy listener,
`baidu_direct_tcp_ms` remains a direct connection from the benchmark host, and
`baidu_via_proxy_ms` is the full connection through that external proxy.
`--upstream-ip` is ignored when `--benchmark-proxy` is set.
The no-`--benchmark-proxy` mode tests the literal built-in BGP IP list; those
rows are already IP addresses and therefore do not use DNS. Use the
`socks5h://` mode when the proxy itself must resolve a hostname such as
`cloudnproxy.baidu.com`.

The benchmark uses the Apple CDN upload endpoint from iNetSpeed-CLI by default;
the download URL itself cannot accept an upload:

```sh
python3 baidu_proxy.py \
  --benchmark \
  --upstream-ip 180.101.50.208 \
  --benchmark-upload-bytes 8388608
```

The Apple endpoint uses `PUT` with chunked transfer encoding, which is the
default. To use another endpoint, pass `--benchmark-upload-url URL`; for a
generic POST endpoint, also add `--benchmark-upload-method POST`.
The program sends zero-filled chunks through the selected cloudnproxy IP,
waits for the upload endpoint's response, calculates `upload_mbps`, and then
discards everything. It does not use the installer download URL for uploads;
that URL is a GET-only resource and would not provide a valid upload speed.

Use `--no-benchmark-upload` when you want to run only the download and latency
tests. With the default 2 MiB cap, a full benchmark uploads up to 2 MiB per
candidate IP.

The `iNetSpeed-CLI --endpoint` option and this program's `--upstream-ip` have
different meanings. iNetSpeed's endpoint is an Apple CDN address; here,
`--upstream-ip` selects the `cloudnproxy.baidu.com` ingress address, while the
Apple hostname remains the upload target inside the CONNECT tunnel.

To expose only one local protocol, use `--protocol http` or `--protocol
socks5`. Keep the listener bound to `127.0.0.1`; binding to `0.0.0.0` creates an
unauthenticated open proxy unless it is protected separately.

## Important limitation

This is a forward proxy. It does not transparently intercept arbitrary system
TCP traffic. True transparent interception requires OS-level redirection such
as TPROXY and a way to recover the original destination address.

The Lua callback treats the first upstream response as a successful handshake
without checking its HTTP status. This implementation requires a `2xx` status
and returns an error to the local client otherwise.

## Test

```sh
python3 -m unittest -v test_baidu_proxy.py
```
