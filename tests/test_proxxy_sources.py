import asyncio
import importlib
import json


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


class MapSession:
    def __init__(self, mapping: dict[str, str]) -> None:
        self.mapping = mapping

    async def get(self, url, timeout=10):
        return FakeResponse(self.mapping[url])


def test_fetch_proxxy_sources(monkeypatch):
    sp = importlib.import_module("scrape_proxies")
    monkeypatch.setattr(sp, "PROXXY_SOURCES", {"HTTP": ["http://example.com"]})

    async def fake_session():
        text = "http://1.1.1.1:1\ninvalid\n2.2.2.2:2 extra\n[2001:db8::1]:8080"
        return FakeSession(text)

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
    assert proxies == ["1.1.1.1:1", "2.2.2.2:2", "2001:db8::1:8080"]


def test_proxyspider_extract():
    sp = importlib.import_module("scrape_proxies")
    spider = sp.ProxySpider()
    html = "<p>1.2.3.4:80</p> other 5.6.7.8:1080"
    assert spider.extract_proxies(html) == ["1.2.3.4:80", "5.6.7.8:1080"]


def test_collect_proxies_by_type(monkeypatch, tmp_path):
    sp = importlib.import_module("scrape_proxies")
    mapping = {
        "http://h": "http://1.1.1.1:1\n",
        "http://s5": "[2001:db8::1]:1080\ninvalid",
    }
    monkeypatch.setattr(sp, "PROXXY_SOURCES", {"HTTP": ["http://h"], "SOCKS5": ["http://s5"]})

    async def fake_session():
        return MapSession(mapping)

    monkeypatch.setattr(sp, "get_aiohttp_session", fake_session)

    res = asyncio.run(sp.collect_proxies_by_type())
    assert res == {"HTTP": ["1.1.1.1:1"], "SOCKS5": ["2001:db8::1:1080"]}

    out = tmp_path / "out.json"
    asyncio.run(sp.save_proxies_json(str(out)))
    saved = json.loads(out.read_text())
    assert saved == res


def test_dedup_across_sources(monkeypatch):
    sp = importlib.import_module("scrape_proxies")
    mapping = {
        "http://a": "1.1.1.1:1\n2.2.2.2:2\n",
        "http://b": "2.2.2.2:2\n3.3.3.3:3\n",
    }
    monkeypatch.setattr(sp, "PROXXY_SOURCES", {"HTTP": ["http://a", "http://b"]})

    async def fake_session():
        return MapSession(mapping)

    monkeypatch.setattr(sp, "get_aiohttp_session", fake_session)

    res = asyncio.run(sp.collect_proxies_by_type())
    assert res == {"HTTP": ["1.1.1.1:1", "2.2.2.2:2", "3.3.3.3:3"]}

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
    assert proxies == ["1.1.1.1:1", "2.2.2.2:2", "3.3.3.3:3"]
