import gzip
import os
import sys
import types
import ssl
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

# Provide minimal stub for optional proxyhub dependency
proxyhub = types.ModuleType('proxyhub')
proxyhub.SOURCE_LIST = []
def fetch_source(url):
    return []
proxyhub.fetch_source = fetch_source
sys.modules.setdefault('proxyhub', proxyhub)

# Some packages used only for type hints might not expose the expected classes.
import aiofiles  # type: ignore
if not hasattr(aiofiles, 'BaseFile'):
    class _BF:  # minimal stub for type checks
        pass
    aiofiles.BaseFile = _BF  # type: ignore

from scrape_proxies import normalize_proxy, _write_gzip, bencode, bdecode, check_tls

CERT = """-----BEGIN CERTIFICATE-----
MIIDCTCCAfGgAwIBAgIUavROruD4wmEVjyoQgGzCgLukod0wDQYJKoZIhvcNAQEL
BQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI1MDYxOTE0NTU1M1oXDTI1MDYy
MDE0NTU1M1owFDESMBAGA1UEAwwJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEAypp1RMUhdfGJ5oAicFsgPZ2ERtWuSdx9Z2JMWjHe6eEX
MIEesz/KWQHCRHUeKLuLuL6lisbD7sRj+bRvd4qNdjIWY2R7NU+jF1Ut9WiE81mS
o9yp0HEDjz122FwtQMizU30UVVtI0gi7br53RvzmFYh0zy2ciXeJWsKtbvseK3QZ
9G+d8EUHlU8FnqKT2QdosqaUpgeBQ7QpgzdGpxnAoPAk3SS06HkiMxCgaSfVANFs
g2Ca0QMYq/0uPC/m1fAHNIIXcDXTlyOEJxFTTIYvWuJXXfuXortOw2v/Ll3ilcQ6
KSGUYNv/xuhrpJFIUTHZ4svh/Z6hjkLnkO5Aebvq5QIDAQABo1MwUTAdBgNVHQ4E
FgQU4cliSsl1T4AwxJyBc0GteHlyPrQwHwYDVR0jBBgwFoAU4cliSsl1T4AwxJyB
c0GteHlyPrQwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAwYWF
ADmg1fVWONEVtKdnXYN4XNVcGRVpmeW2bmB85zF6uvFwB8cmQnwjuII0aZKb8ORC
Np16VR1vBfeYSReN0dt3NWpqZqxGEmFbKRkvZUexgNpU296ykfqHQmwWlzBvV2iS
TnHGpGdbLFGxBar2/YF1XiKKnr1Go6mrw2KE36IJwBaLAmVwfKbULEkWo0DumimC
zSNN9KA/PMnAWx4BkJCzo4LPLxwKpCBb1i4ODw03w4mOm6dqcrJzcAcSvZbfXUja
qYixulCFjKS/WNwhaTqvVxV7bK5xSAMGMyi68FFHBj/sy9DQEe2+tZvEKEasK2Yz
yDXfN9zjImgVh+q05g==
-----END CERTIFICATE-----"""

KEY = """-----BEGIN PRIVATE KEY-----
MIIEugIBADANBgkqhkiG9w0BAQEFAASCBKQwggSgAgEAAoIBAQDKmnVExSF18Ynm
gCJwWyA9nYRG1a5J3H1nYkxaMd7p4RcwgR6zP8pZAcJEdR4ou4u4vqWKxsPuxGP5
tG93io12MhZjZHs1T6MXVS31aITzWZKj3KnQcQOPPXbYXC1AyLNTfRRVW0jSCLtu
vndG/OYViHTPLZyJd4lawq1u+x4rdBn0b53wRQeVTwWeopPZB2iyppSmB4FDtCmD
N0anGcCg8CTdJLToeSIzEKBpJ9UA0WyDYJrRAxir/S48L+bV8Ac0ghdwNdOXI4Qn
EVNMhi9a4ldd+5eiu07Da/8uXeKVxDopIZRg2//G6GukkUhRMdniy+H9nqGOQueQ
7kB5u+rlAgMBAAECgf90u4nVlb8xtXk+1ZUCJ37sAVW1emhxJhka+AgF77YACzDR
QZPus1Ji9iB4UQKPdX+LckzvKJa7e2we81dGCQ54i2Na4QocLUZKq0lPnGj9zR4w
S3OMJZFndoKDJpjsOrcX43lTtMTAP0e/Bv6yaAQpY/XpaN5IVhdNs905lHZNkhDs
X2TtOb9wr852GlAgvUXSjfDWj1UFYjDSY56NxGcNntwrgqTVHRbjl7pd65hMcHqw
abx8Gl4+MICxNGgFgaRcGnQFuq9X4oMEbKRO9n0Xsnyi9HuryjAZti6v0Akd70L4
oppZ/2U/Z+Rq2HZ9R0k3doVI9dADOZ0O0Z4znUECgYEA5s1AxMCta0Vq7ygndTvo
qhzW0mFesJJdKvF1VZa7hoCiejGmbY1YBh0CkEut7aicS0rKNHnM9hNc+8WKt5gp
0QVFYl2ayk1b/6TLiIeO14QqpD2+jDWzDHg1iHM4F0nSRRsqbyrkeorAEpyFuy0T
qQ3kvs79DW+lKRDsZV4wCGECgYEA4LkUQ2fKgf2QWeTZO7fuUgDZtyxcJ1T6o/ZI
jV3Mg1Uy6mH0n0a5HBTe/7J61nn9+fJ7oKkQNRZbNwIAIdTsHGIC47crmTdvQP2c
S6rAKAOFOsptbwDzrTkp0uTPfw2D9TfMfp3ti8BoUmVauo2R/2AvntjApmP5gv+w
2Hf/YQUCgYBg0Kqhnf1g6R6hMaPTnozLhwtp9qRExzDDycOhYnhJRH5jaZ5ZiBfr
gJHJu6U68yaUwsutVYZvltHDXysANpkb7+0aBQ/gWrEDvLoQDGUT7IICoU/j+saf
rXEvSr21rybADFQxi7mJ2dgWNog2awM7P/O7QpKN505NuqafIvJdIQKBgFaL8Rnk
p0FY/ncgg+lT9Rzv5ul81CDxwXXULC0FqvYJogpSn3uYKUJ/Z0Li4hwn74CLusEt
W2iWq5qL0rE055omxSYeLVRc3SQSiFc787V1ZaI2w960ZySXl1v5c1BjTCbszn0V
JZ9lAsh48HBYhZns2Wo74DY02qtw/hLgZCJhAoGAOOuOkxKwn8+hjatK4E5TyRn9
ofh6cVzO7ML2+UcdxypVlDv5wjzvlojBduoWqFrZZU4oYGLFW7q0E+xLMFCdEDkh
nsrgxxRq3rskPDh+Bkrv/03w+u8/VUFyk9T0QSK8/O31Qv0P5Tuj3pS5oPnvYPzl
uZ7vo0sZRf7SedYmQ08=
-----END PRIVATE KEY-----"""


def test_normalize_proxy_basic():
    assert normalize_proxy('http://1.2.3.4:80') == 'http:1.2.3.4:80'
    assert normalize_proxy('1.2.3.4:8080') == 'http:1.2.3.4:8080'
    assert normalize_proxy('socks5://5.6.7.8:1080') == 'socks5:5.6.7.8:1080'
    assert normalize_proxy('foo://1.2.3.4:1') == 'other:1.2.3.4:1'
    assert normalize_proxy('bad') is None


def test_write_gzip(tmp_path):
    path = tmp_path / 'out.gz'
    _write_gzip(str(path), ['a', 'b'], 'at')
    with gzip.open(path, 'rt') as f:
        data = f.read().splitlines()
    assert data == ['a', 'b']


def test_bencode_roundtrip():
    value = {'a': [1, b'2']}
    encoded = bencode(value)
    assert bdecode(encoded) == {b'a': [1, b'2']}


def test_main_and_files(monkeypatch, tmp_path):
    import asyncio
    import scrape_proxies as sp

    async def fake_collect():
        return {"HTTP": ["1.1.1.1:1"]}

    async def fake_classify(p, timeout=2.0):
        return "http"

    recorded = {}

    async def fake_check_tls(proxy, proto, timeout=5.0, **kwargs):
        recorded["timeout"] = timeout
        return True

    class FakeSemaphore(asyncio.Semaphore):
        def __init__(self, value):
            recorded["concurrency"] = value
            super().__init__(value)

    monkeypatch.setattr(sp, "collect_proxies_by_type", fake_collect)
    monkeypatch.setattr(sp, "classify_proxy", fake_classify)
    monkeypatch.setattr(sp, "check_tls", fake_check_tls)
    monkeypatch.setattr(sp.asyncio, "Semaphore", FakeSemaphore)

    asyncio.run(sp.main([
        "--timeout", "3", "--concurrency", "2", "--stats-interval", "0.1", "--output-dir", str(tmp_path)
    ]))

    assert recorded["timeout"] == 3
    assert recorded["concurrency"] == 2
    assert (tmp_path / "http.txt").exists()
    assert (tmp_path / "http_working.txt").exists()
    data = json.loads((tmp_path / "stats.json").read_text())
    assert data["total"] == 1
    assert data["passed_filter1"] == 1


def test_check_tls(tmp_path):
    import asyncio
    ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    cert = tmp_path / "cert.pem"
    key = tmp_path / "key.pem"
    cert.write_text(CERT)
    key.write_text(KEY)
    ssl_ctx.load_cert_chain(cert, key)

    async def handle(reader, writer):
        await reader.read(1)
        writer.close()

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    server = loop.run_until_complete(
        asyncio.start_server(handle, "127.0.0.1", 0, ssl=ssl_ctx)
    )
    port = server.sockets[0].getsockname()[1]

    try:
        assert loop.run_until_complete(
            check_tls(f"127.0.0.1:{port}", "direct", timeout=1, target_host="127.0.0.1", target_port=port)
        )
        assert not loop.run_until_complete(
            check_tls(f"127.0.0.1:{port+1}", "direct", timeout=1, target_host="127.0.0.1", target_port=port+1)
        )
    finally:
        server.close()
        loop.run_until_complete(server.wait_closed())
        loop.close()
