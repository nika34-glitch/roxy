import importlib
import sys
import types
import json
import asyncio


def _prepare(monkeypatch, config_path=None):
    if 'scrape_proxies' in sys.modules:
        del sys.modules['scrape_proxies']
    proxyhub = types.ModuleType('proxyhub')
    monkeypatch.setitem(sys.modules, 'proxyhub', proxyhub)
    if config_path:
        monkeypatch.setenv('SCORING_CONFIG', str(config_path))
    else:
        monkeypatch.delenv('SCORING_CONFIG', raising=False)
    return importlib.import_module('scrape_proxies')


def test_default_mode_strict(monkeypatch):
    sp = _prepare(monkeypatch)
    assert sp.MODE == 'strict'
    assert sp.CRITICAL_MIN == 325
    assert sp.WEIGHTS['geo'] == 48


def test_lenient_quarantine(monkeypatch, tmp_path):
    cfg = {
        "mode": "lenient",
        "lenient": {
            "CRITICAL_MIN": 300,
            "OVERALL_MIN": 600,
            "WEIGHTS": {
                "ip_rep": 120,
                "proxy_type": 152,
                "tls_reach": 152,
                "ja3": 80,
                "fresh": 83,
                "nettype": 83,
                "asn": 83,
                "err_rate": 48,
                "geo": 24,
                "latency": 24,
            },
        },
    }
    path = tmp_path / 'cfg.json'
    path.write_text(json.dumps(cfg))
    sp = _prepare(monkeypatch, path)

    async def fake_score(p, ctx, return_all=False):
        mapping = {
            'socks5:1.1.1.1:1': ('socks5:1.1.1.1:1', 700, {'critical': 400}),
            'socks5:2.2.2.2:2': ('socks5:2.2.2.2:2', 550, {'critical': 320}),
            'socks5:3.3.3.3:3': ('socks5:3.3.3.3:3', 400, {'critical': 200}),
        }
        return mapping[p]

    async def nop(*args, **kwargs):
        return None

    monkeypatch.setattr(sp, '_score_single_proxy', fake_score)
    monkeypatch.setattr(sp, 'load_blacklists', nop)
    monkeypatch.setattr(sp, 'load_ja3_sets', nop)
    monkeypatch.setattr(sp, 'load_asn_metadata', nop)
    monkeypatch.setattr(sp, 'load_geoip', nop)
    monkeypatch.setattr(sp, 'load_allow_lists', lambda path=None: None)

    good, quarantine = asyncio.run(sp.filter_p2([
        'socks5:1.1.1.1:1',
        'socks5:2.2.2.2:2',
        'socks5:3.3.3.3:3',
    ]))
    assert good == [('socks5:1.1.1.1:1', 700)]
    assert quarantine == [('socks5:2.2.2.2:2', 550)]
