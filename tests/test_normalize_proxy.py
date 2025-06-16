import types
import sys

sys.modules["proxyhub"] = types.SimpleNamespace(
    SOURCE_LIST=[], fetch_source=lambda url: []
)
import scrape_proxies


def test_normalize_valid():
    assert scrape_proxies.normalize_proxy("1.2.3.4:8080") == "http:1.2.3.4:8080"
    assert (
        scrape_proxies.normalize_proxy("socks5://1.2.3.4:9050") == "socks5:1.2.3.4:9050"
    )


def test_normalize_invalid():
    assert scrape_proxies.normalize_proxy("not an ip") is None
    assert scrape_proxies.normalize_proxy("http://256.0.0.1:80") is None
    assert scrape_proxies.normalize_proxy("http://1.1.1.1:99999") is None
