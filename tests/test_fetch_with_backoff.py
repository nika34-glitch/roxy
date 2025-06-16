import httpx
import types
import sys
import pytest

sys.modules["proxyhub"] = types.SimpleNamespace(
    SOURCE_LIST=[], fetch_source=lambda url: []
)
import scrape_proxies


@pytest.mark.asyncio
async def test_fetch_with_backoff_httpx(monkeypatch):
    async def get_aiohttp_session():
        transport = httpx.MockTransport(lambda r: httpx.Response(200, text="ok"))
        return httpx.AsyncClient(transport=transport)

    monkeypatch.setattr(scrape_proxies, "USE_HTTP2", True)
    monkeypatch.setattr(scrape_proxies, "get_aiohttp_session", get_aiohttp_session)
    text = await scrape_proxies.fetch_with_backoff("http://example.com")
    assert text == "ok"
