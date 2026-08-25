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
