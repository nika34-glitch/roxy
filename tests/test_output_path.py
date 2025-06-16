import os
import types
import sys

sys.modules["proxyhub"] = types.SimpleNamespace(
    SOURCE_LIST=[], fetch_source=lambda url: []
)
import scrape_proxies


def test_output_path_creates_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(scrape_proxies, "OUTPUT_DIR", str(tmp_path / "out"))
    monkeypatch.setattr(scrape_proxies, "OUTPUT_FILE", "proxies.txt")
    path = scrape_proxies._output_path("http")
    assert os.path.isdir(scrape_proxies.OUTPUT_DIR)
    assert path.endswith("http_proxies.txt")
