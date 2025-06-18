import json
import asyncio
import importlib
import types

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import scrape_proxies as sp


def test_filter_p2_quarantine(tmp_path, monkeypatch):
    cfg = {
        "mode": "lenient",
        "lenient": {
            "CRITICAL_MIN": 300,
            "OVERALL_MIN": 600,
            "QUARANTINE_MIN": 500,
            "WEIGHTS": {"geo": 24, "latency": 24, "ja3": 80, "ip_rep": 120},
        },
    }
    path = tmp_path / "cfg.json"
    path.write_text(json.dumps(cfg))
    sp.load_scoring_config(str(path))

    async def noop():
        return None
    monkeypatch.setattr(sp, "load_asn_metadata", noop)
    monkeypatch.setattr(sp, "load_blacklists", noop)
    monkeypatch.setattr(sp, "load_ja3_sets", noop)
    monkeypatch.setattr(sp, "load_geoip", noop)

    async def fake_score(p, ctx):
        return (p, 550, {})

    monkeypatch.setattr(sp, "_score_single_proxy", fake_score)
    approved, quarantine = asyncio.run(sp.filter_p2(["socks5://1.2.3.4:1080"]))
    assert approved == []
    assert len(quarantine) == 1
