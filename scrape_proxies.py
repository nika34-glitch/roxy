# ProxyHub scraping utilities

import asyncio
import importlib.util
import logging
import re
import random
import sys
import types
from pathlib import Path
from typing import Any, List, Optional
import ipaddress
import gzip
import aiohttp
import json
import os

__all__ = [
    "fetch_proxies",
    "normalize_proxy",
    "_write_gzip",
    "bencode",
    "bdecode",
]

_log = logging.getLogger(__name__)

PROTOCOL_RE = re.compile(r"^(https?|socks4|socks5)$", re.I)

# Defaults and fallbacks for optional proxyhub/proXXy features
PROXXY_SOURCES = {}

try:
    from proxyhub import SOURCE_LIST, fetch_source
except Exception:  # pragma: no cover - optional dependency
    SOURCE_LIST: list[str] = []

    async def fetch_source(url: str) -> List[str]:
        return []

MODE = "strict"
CRITICAL_MIN = 120
OVERALL_MIN = 250
WEIGHTS = {
    "ip_rep": 179,
    "tls_reach": 152,
}

SCORING_CONFIG = os.getenv(
    "SCORING_CONFIG",
    str(Path(__file__).resolve().parent / "data" / "scoring_config.json"),
)


def load_scoring_config(path: Optional[str] = None) -> None:
    """Load scoring configuration from a JSON or YAML file."""

    global MODE, CRITICAL_MIN, OVERALL_MIN, WEIGHTS

    file_path = path or SCORING_CONFIG
    if not os.path.exists(file_path):
        return

    try:
        with open(file_path, "r") as f:
            text = f.read()
        if file_path.endswith((".yml", ".yaml")):
            try:
                import yaml  # type: ignore
            except Exception:
                yaml = None  # pragma: no cover - optional dependency
            cfg = yaml.safe_load(text) if yaml else json.loads(text)
        else:
            cfg = json.loads(text)
    except Exception as exc:  # pragma: no cover - invalid config
        _log.error("Error loading scoring config %s: %s", file_path, exc)
        return

    mode = str(cfg.get("mode", MODE)).lower()
    if mode not in {"strict", "lenient"}:
        mode = "strict"
    MODE = mode

    section = cfg.get(mode) if isinstance(cfg.get(mode), dict) else cfg

    CRITICAL_MIN = section.get("CRITICAL_MIN", CRITICAL_MIN)
    OVERALL_MIN = section.get("OVERALL_MIN", OVERALL_MIN)
    weights = section.get("WEIGHTS") or section.get("weights")
    if isinstance(weights, dict):
        for k, v in weights.items():
            if k in WEIGHTS:
                WEIGHTS[k] = v


load_scoring_config()

_PROVIDER_MODULE = None


def _load_provider_module():
    """Dynamically load proxyhub's providers module with minimal stubs."""
    global _PROVIDER_MODULE
    if _PROVIDER_MODULE is not None:
        return _PROVIDER_MODULE

    base_path = Path(__file__).resolve().parent / "proxyhub" / "proxyhub" / "providers.py"

    # minimal proxyhub package stubs for relative imports
    pkg = types.ModuleType("proxyhub")
    pkg.__path__ = [str(base_path.parent)]
    sys.modules.setdefault("proxyhub", pkg)

    errors = types.ModuleType("proxyhub.errors")

    class BadStatusError(Exception):
        pass

    errors.BadStatusError = BadStatusError
    sys.modules.setdefault("proxyhub.errors", errors)

    utils = types.ModuleType("proxyhub.utils")
    utils.log = _log
    utils.IPPattern = re.compile(
        r"(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)"
    )
    utils.IPPortPatternGlobal = re.compile(
        r"(?P<ip>(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?))"
        r"(?=.*?(?:(?:(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?))|(?P<port>\d{2,5})))",
        flags=re.DOTALL,
    )

    def get_headers(rv: bool = False):
        _rv = str(random.randint(1000, 9999)) if rv else ""
        headers = {
            "User-Agent": f"PxBroker/0.0/{_rv}",
            "Accept": "*/*",
            "Accept-Encoding": "gzip, deflate",
            "Pragma": "no-cache",
            "Cache-control": "no-cache",
            "Cookie": "cookie=ok",
            "Referer": "https://www.google.com/",
        }
        return headers if not rv else (headers, _rv)

    utils.get_headers = get_headers
    sys.modules.setdefault("proxyhub.utils", utils)

    spec = importlib.util.spec_from_file_location("proxyhub.providers", base_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules["proxyhub.providers"] = module
    spec.loader.exec_module(module)  # type: ignore
    _PROVIDER_MODULE = module
    return module


async def load_blacklists() -> None:
    """Placeholder for blacklist loader."""

    return None


async def _score_single_proxy(proxy: str, ctx: Any, return_all: bool = False):
    """Placeholder scoring function; overridden in tests."""

    return None


async def filter_p2(
    proxies: List[str],
) -> tuple[List[tuple[str, int]], List[tuple[str, int]]]:
    """Filter proxies based on scoring heuristics."""

    proxies = [p for p in proxies if p.split(":", 1)[0].lower() in {"socks4", "socks5"}]
    if not proxies:
        return [], []

    async def score(p: str) -> tuple[str, int, dict[str, int]]:
        res = await _score_single_proxy(p, None, return_all=True)
        assert res is not None
        return res

    tasks = [asyncio.create_task(score(p)) for p in proxies]
    scored: List[tuple[str, int, dict[str, int]]] = []
    for t in asyncio.as_completed(tasks):
        try:
            res = await t
            scored.append(res)
        except Exception:
            continue

    accepted: List[tuple[str, int]] = []
    quarantine: List[tuple[str, int]] = []
    for norm, score_val, parts in scored:
        crit = parts.get("critical", 0)
        if score_val >= OVERALL_MIN and crit >= CRITICAL_MIN:
            accepted.append((norm, score_val))
        elif MODE == "lenient" and 500 <= score_val < 600:
            quarantine.append((norm, score_val))

    return accepted, quarantine


async def get_aiohttp_session() -> aiohttp.ClientSession:
    """Return an ``aiohttp`` session used for network requests."""

    return aiohttp.ClientSession()


async def fetch_proxxy_sources() -> Any:
    """Fetch all proxy sources defined by PROXXY_SOURCES."""

    urls: List[str] = []
    for lst in PROXXY_SOURCES.values():
        urls.extend(lst)

    session = await get_aiohttp_session()
    tasks = {asyncio.create_task(session.get(url, timeout=10)): url for url in urls}
    batch: List[str] = []
    for t in asyncio.as_completed(tasks):
        url = tasks[t]
        try:
            resp = await t
            async for raw in resp.content:
                line = raw.decode(errors="ignore").strip()
                if re.match(r"\d+\.\d+\.\d+\.\d+:\d+", line):
                    batch.append(line)
                    if len(batch) >= 1000:
                        yield batch
                        batch = []
        except Exception as e:  # pragma: no cover - network errors
            _log.error("proXXy source error %s: %s", url, e)
    if batch:
        yield batch


class ProxySpider:
    """Simple spider used for parsing HTML pages of proxies."""

    def extract_proxies(self, html_content: str) -> List[str]:
        pattern = re.compile(r"\d{1,3}(?:\.\d{1,3}){3}:\d+")
        return pattern.findall(html_content)

def normalize_proxy(entry: str) -> Optional[str]:
    """Return proxy as ``proto:ip:port`` if valid, else ``None``."""
    entry = entry.strip()
    if not entry:
        return None
    if "://" in entry:
        proto, rest = entry.split("://", 1)
    elif ";" in entry:
        proto, ip, port = entry.split(";", 2)
        rest = f"{ip}:{port}"
    else:
        parts = entry.split(":")
        if len(parts) == 2:
            proto, rest = "http", entry
        elif len(parts) == 3:
            proto, rest = parts[0], f"{parts[1]}:{parts[2]}"
        else:
            return None

    proto = proto.lower()
    ip_port = rest.split(":")
    if len(ip_port) != 2:
        return None
    ip, port_str = ip_port
    if not port_str.isdigit():
        return None
    port = int(port_str)
    if not (1 <= port <= 65535):
        return None
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return None
    if not PROTOCOL_RE.match(proto):
        proto = "other"
    return f"{proto}:{ip}:{port}"


def _write_gzip(path: str, items: List[str], mode: str) -> None:
    """Write ``items`` to a gzipped file using binary mode."""

    mode_bin = mode.replace("t", "") + "b"
    with gzip.open(path, mode_bin) as f:
        buf: List[str] = []
        size = 0
        for line in items:
            line = line + "\n"
            buf.append(line)
            size += len(line)
            if size >= 65536:
                f.write("".join(buf).encode())
                buf = []
                size = 0
        if buf:
            f.write("".join(buf).encode())


def bencode(value: Any) -> bytes:
    """Minimal bencode encoder supporting ints, bytes, str, lists and dicts."""
    if isinstance(value, int):
        return b"i" + str(value).encode() + b"e"
    if isinstance(value, bytes):
        return str(len(value)).encode() + b":" + value
    if isinstance(value, str):
        bval = value.encode()
        return str(len(bval)).encode() + b":" + bval
    if isinstance(value, list):
        return b"l" + b"".join(bencode(v) for v in value) + b"e"
    if isinstance(value, dict):
        items = []
        for k in sorted(value.keys()):
            key = k.encode() if isinstance(k, str) else k
            items.append(str(len(key)).encode() + b":" + key)
            items.append(bencode(value[k]))
        return b"d" + b"".join(items) + b"e"
    raise TypeError(f"unsupported type: {type(value)!r}")


def bdecode(data: bytes) -> Any:
    """Decode a subset of the bencode format."""

    def _parse(idx: int) -> tuple[Any, int]:
        token = data[idx : idx + 1]
        if token == b"i":
            end = data.index(b"e", idx + 1)
            return int(data[idx + 1 : end]), end + 1
        if token == b"l":
            idx += 1
            lst = []
            while data[idx : idx + 1] != b"e":
                item, idx = _parse(idx)
                lst.append(item)
            return lst, idx + 1
        if token == b"d":
            idx += 1
            d: dict[bytes, Any] = {}
            while data[idx : idx + 1] != b"e":
                key, idx = _parse(idx)
                val, idx = _parse(idx)
                d[key if isinstance(key, bytes) else bytes()] = val
            return d, idx + 1
        if token.isdigit():
            colon = data.index(b":", idx)
            length = int(data[idx:colon])
            start = colon + 1
            end = start + length
            return data[start:end], end
        raise ValueError("invalid bencode")

    value, pos = _parse(0)
    if pos != len(data):
        raise ValueError("trailing data")
    return value

async def fetch_proxies(types: List[str] = None, limit: int = 100) -> List[str]:
    """Asynchronously collect up to ``limit`` proxies from all sources."""

    if types is None:
        types = ["HTTP", "HTTPS"]

    provider_mod = _load_provider_module()
    providers = provider_mod.PROVIDERS

    tasks = [p.get_proxies() for p in providers]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    collected = []
    seen = set()

    for provider, result in zip(providers, results):
        if isinstance(result, Exception):  # pragma: no cover - network errors
            _log.warning(
                "provider %s failed: %s",
                getattr(provider, "domain", provider.url),
                result,
            )
            continue
        for host, port, proto in result:
            if proto and not set(proto) & set(types):
                continue
            proxy = f"{host}:{port}"
            if proxy not in seen:
                seen.add(proxy)
                collected.append(proxy)
                if len(collected) >= limit:
                    return collected
    return collected
