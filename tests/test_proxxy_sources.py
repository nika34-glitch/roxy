import asyncio
import importlib


class FakeResponse:
    def __init__(self, text: str) -> None:
        self._lines = [line.encode() for line in text.splitlines()]

    def __aiter__(self):
        async def gen():
            for line in self._lines:
                yield line

        return gen()

    @property
    def content(self):
        return self


class FakeSession:
    def __init__(self, text: str) -> None:
        self.text = text

    async def get(self, url, timeout=10):
        return FakeResponse(self.text)


def test_fetch_proxxy_sources(monkeypatch):
    sp = importlib.import_module("scrape_proxies")
    monkeypatch.setattr(sp, "PROXXY_SOURCES", {"HTTP": ["http://example.com"]})

    async def fake_session():
        return FakeSession("1.1.1.1:1\ninvalid\n2.2.2.2:2")

    monkeypatch.setattr(sp, "get_aiohttp_session", fake_session)

    def fake_as_completed(iterable):
        for item in iterable:
            yield item

    monkeypatch.setattr(asyncio, "as_completed", fake_as_completed)

    async def run():
        out = []
        async for batch in sp.fetch_proxxy_sources():
            out.extend(batch)
        return out

    proxies = asyncio.run(run())
    assert proxies == ["1.1.1.1:1", "2.2.2.2:2"]


def test_proxyspider_extract():
    sp = importlib.import_module("scrape_proxies")
    spider = sp.ProxySpider()
    html = "<p>1.2.3.4:80</p> other 5.6.7.8:1080"
    assert spider.extract_proxies(html) == ["1.2.3.4:80", "5.6.7.8:1080"]
