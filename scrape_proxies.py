import asyncio
import importlib.util
import logging
import re
import random
import sys
import types
import ipaddress
import os
import json
import gzip
import ssl
import functools
from pathlib import Path
from typing import List, AsyncGenerator, Any

__all__ = [
    "fetch_proxies",
    "probe_proxies",
    "classify_proxy",
    "normalize_proxy",
    "_write_gzip",
    "bencode",
    "bdecode",
    "PROXXY_SOURCES",
    "load_proxy_sources",
    "PROXY_SOURCES_PATH",
    "get_aiohttp_session",
    "fetch_proxxy_sources",
    "collect_proxies_by_type",
    "save_proxies_json",
    "ProxySpider",
    "SOURCE_LIST",
    "fetch_source",
    "MODE",
    "CRITICAL_MIN",
    "OVERALL_MIN",
    "WEIGHTS",
    "filter_p2",
]

_log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# ProxyHub provider loader
# ---------------------------------------------------------------------------
_PROVIDER_MODULE = None

def _load_provider_module():
    """Dynamically load proxyhub's providers module with minimal stubs."""
    global _PROVIDER_MODULE
    if _PROVIDER_MODULE is not None:
        return _PROVIDER_MODULE

    base_path = Path(__file__).resolve().parent / "proxyhub" / "proxyhub" / "providers.py"

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
    utils.IPPattern = re.compile(r"(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)")
    utils.IPPortPatternGlobal = re.compile(
        r"(?P<ip>(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?))" \
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

# ---------------------------------------------------------------------------
# ProxyHub fallbacks
# ---------------------------------------------------------------------------
try:
    from proxyhub import SOURCE_LIST, fetch_source  # type: ignore
except Exception:  # pragma: no cover - missing dependency
    SOURCE_LIST = []
    async def fetch_source(url: str) -> List[str]:
        return []
    _log.warning("proxyhub module not found or incomplete, disabling ProxyHub scraping")

# ---------------------------------------------------------------------------
# Scoring configuration
# ---------------------------------------------------------------------------
WEIGHTS = {"ip_rep": 179, "tls_reach": 152}
CRITICAL_MIN = 120
OVERALL_MIN = 250
MODE = "strict"
SCORING_CONFIG = os.getenv(
    "SCORING_CONFIG",
    str(Path(__file__).resolve().parent / "data" / "scoring_config.json"),
)
try:
    import yaml  # type: ignore
except Exception:  # pragma: no cover - optional dependency
    yaml = None  # type: ignore

def load_scoring_config(path: str | None = None) -> None:
    global MODE, CRITICAL_MIN, OVERALL_MIN, WEIGHTS
    file_path = path or SCORING_CONFIG
    if not os.path.exists(file_path):
        return
    try:
        with open(file_path, "r") as f:
            text = f.read()
        if file_path.endswith((".yml", ".yaml")) and yaml is not None:
            cfg = yaml.safe_load(text)
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

# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------
PROTOCOL_RE = re.compile(r"^(https?|socks4|socks5)$", re.I)

@functools.lru_cache(maxsize=100000)
def normalize_proxy(entry: str) -> str | None:
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

# ---------------------------------------------------------------------------
# ProXXy sources and spider
# ---------------------------------------------------------------------------

PROXY_SOURCES_PATH = os.getenv(
    "PROXY_SOURCES_PATH",
    str(Path(__file__).resolve().parent / "data" / "proxy_sources.json"),
)


def load_proxy_sources(path: str = PROXY_SOURCES_PATH) -> dict[str, list[str]]:
    """Return mapping of proxy type to source URLs from *path* if it exists."""

    if os.path.exists(path):
        try:
            with open(path, "r") as fh:
                data = json.load(fh)
            if isinstance(data, dict):
                result = {}
                for k in ("HTTP", "SOCKS4", "SOCKS5", "HTTPS"):
                    urls = data.get(k)
                    if isinstance(urls, list):
                        result[k] = [str(u) for u in urls]
                if result:
                    return result
        except Exception as exc:  # pragma: no cover - invalid file
            _log.error("error loading %s: %s", path, exc)

    return {
        "HTTP": ["https://example.com/http.txt"],
        "SOCKS4": ["https://example.com/socks4.txt"],
        "SOCKS5": ["https://example.com/socks5.txt"],
        "HTTPS": ["https://example.com/https.txt"],
    }


PROXXY_SOURCES = load_proxy_sources()

IP_PORT_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}:\d+$")
REQUEST_TIMEOUT = 10

aiohttp_session: Any | None = None

async def get_aiohttp_session() -> Any:
    global aiohttp_session
    if aiohttp_session is None:
        try:
            import aiohttp  # type: ignore
        except Exception as exc:  # pragma: no cover - optional dependency
            raise RuntimeError("aiohttp required") from exc
        aiohttp_session = aiohttp.ClientSession()
    return aiohttp_session

async def fetch_proxxy_sources() -> AsyncGenerator[List[str], None]:
    sources = PROXXY_SOURCES
    urls = [u for lst in sources.values() for u in lst]
    session = await get_aiohttp_session()
    tasks = {asyncio.create_task(session.get(url, timeout=REQUEST_TIMEOUT)): url for url in urls}
    batch: List[str] = []
    for task in asyncio.as_completed(tasks):
        url = tasks[task]
        try:
            resp = await task
            async for raw_line in resp.content:
                line = raw_line.decode(errors="ignore").strip()
                if IP_PORT_RE.match(line):
                    batch.append(line)
                    if len(batch) >= 1000:
                        yield batch
                        batch = []
        except Exception as e:  # pragma: no cover - network failures
            _log.error("proXXy source error %s: %s", url, e)
    if batch:
        yield batch


async def collect_proxies_by_type() -> dict[str, List[str]]:
    """Return proxies from all sources grouped by proxy type."""
    result: dict[str, List[str]] = {k: [] for k in PROXXY_SOURCES}
    session = await get_aiohttp_session()
    for proto, urls in PROXXY_SOURCES.items():
        for url in urls:
            try:
                resp = await session.get(url, timeout=REQUEST_TIMEOUT)
                async for raw_line in resp.content:
                    line = raw_line.decode(errors="ignore").strip()
                    if IP_PORT_RE.match(line):
                        result[proto].append(line)
            except Exception as e:  # pragma: no cover - network failures
                _log.error("proXXy source error %s: %s", url, e)
    return result


async def save_proxies_json(path: str) -> None:
    """Write collected proxies to *path* in JSON format."""
    data = await collect_proxies_by_type()
    with open(path, "w") as fh:
        json.dump(data, fh, indent=2, sort_keys=True)

try:
    from scrapy import Spider, Request  # type: ignore
    from scrapy.crawler import CrawlerProcess  # type: ignore
except Exception:  # pragma: no cover - optional dependency
    Spider = Request = object  # type: ignore
    class _DummyCrawler:
        def crawl(self, *_, **__):
            return None
        def start(self) -> None:
            pass
    CrawlerProcess = _DummyCrawler  # type: ignore

class ProxySpider(Spider):
    name = "proxy_spider"
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0 Safari/537.36",
    ]
    custom_settings = {
        "LOG_LEVEL": "ERROR",
        "DOWNLOAD_TIMEOUT": 5,
        "RETRY_TIMES": 2,
        "USER_AGENT": random.choice(user_agents),
    }

    def start_requests(self):
        for protocol, urls in PROXXY_SOURCES.items():
            for url in urls:
                yield Request(url, callback=self.parse, meta={"protocol": protocol})

    def parse(self, response):
        protocol = response.meta["protocol"]
        proxies = self.extract_proxies(response.text)
        self.save_proxies(protocol, proxies)

    def extract_proxies(self, html_content: str) -> List[str]:
        pattern = re.compile(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+")
        return pattern.findall(html_content)

    def save_proxies(self, protocol: str, proxies: List[str]) -> None:
        os.makedirs("output", exist_ok=True)
        file_path = f"output/{protocol}.txt"
        with open(file_path, "a") as f:
            for p in proxies:
                f.write(p + "\n")

# ---------------------------------------------------------------------------
# Scoring helpers used by filter_p2
# ---------------------------------------------------------------------------
async def load_blacklists() -> None:
    return None

async def _score_single_proxy(p: str, ctx: ssl.SSLContext, return_all: bool = False):
    return None

async def filter_p2(proxies: List[str]) -> tuple[List[tuple[str, int]], List[tuple[str, int]]]:
    proxies = [p for p in proxies if p.split(":", 1)[0].lower() in {"socks4", "socks5"}]
    if not proxies:
        return [], []
    await load_blacklists()
    ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2

    async def score(p: str) -> tuple[str, int, dict[str, int]]:
        res = await _score_single_proxy(p, ctx, return_all=True)
        assert res is not None
        return res

    tasks = [asyncio.create_task(score(p)) for p in proxies]
    scored: List[tuple[str, int, dict[str, int]]] = []
    for t in asyncio.as_completed(tasks):
        try:
            res = await t
            if res:
                scored.append(res)
        except Exception:
            continue
    accepted: List[tuple[str, int]] = []
    quarantine: List[tuple[str, int]] = []
    for norm, score, parts in scored:
        crit = parts.get("critical", 0)
        if score >= OVERALL_MIN and crit >= CRITICAL_MIN:
            accepted.append((norm, score))
        elif MODE == "lenient" and 500 <= score < 600:
            quarantine.append((norm, score))
    return accepted, quarantine

# ---------------------------------------------------------------------------
# Minimal async fetcher using ProxyHub providers
# ---------------------------------------------------------------------------
async def fetch_proxies(types: List[str] | None = None, limit: int = 100) -> List[str]:
    if types is None:
        types = ["HTTP", "HTTPS"]
    provider_mod = _load_provider_module()
    providers = provider_mod.PROVIDERS
    tasks = [p.get_proxies() for p in providers]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    collected: List[str] = []
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


EXAMPLE_IP = ipaddress.ip_address("93.184.216.34").packed
SOCKS5_GREETING = b"\x05\x01\x00"
SOCKS4_REQ = b"\x04\x01" + (80).to_bytes(2, "big") + EXAMPLE_IP + b"\x00"
HTTP_GET_REQ = b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n"
HTTPS_CONNECT_REQ = b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"


async def _open_connection(host: str, port: int, timeout: float) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    return await asyncio.wait_for(asyncio.open_connection(host, port), timeout)


async def _try_socks5(host: str, port: int, timeout: float) -> bool:
    try:
        reader, writer = await _open_connection(host, port, timeout)
    except Exception:
        return False
    try:
        writer.write(SOCKS5_GREETING)
        await writer.drain()
        data = await asyncio.wait_for(reader.readexactly(2), timeout)
        return len(data) == 2 and data[0] == 0x05
    except Exception:
        return False
    finally:
        writer.close()
        await writer.wait_closed()


async def _try_socks4(host: str, port: int, timeout: float) -> bool:
    try:
        reader, writer = await _open_connection(host, port, timeout)
    except Exception:
        return False
    try:
        writer.write(SOCKS4_REQ)
        await writer.drain()
        data = await asyncio.wait_for(reader.readexactly(2), timeout)
        return len(data) == 2 and data[0] == 0x00
    except Exception:
        return False
    finally:
        writer.close()
        await writer.wait_closed()


async def _try_http_get(host: str, port: int, timeout: float) -> bool:
    try:
        reader, writer = await _open_connection(host, port, timeout)
    except Exception:
        return False
    try:
        writer.write(HTTP_GET_REQ)
        await writer.drain()
        data = await asyncio.wait_for(reader.read(64), timeout)
        return b"HTTP/1." in data
    except Exception:
        return False
    finally:
        writer.close()
        await writer.wait_closed()


async def _try_https_connect(host: str, port: int, timeout: float) -> bool:
    try:
        reader, writer = await _open_connection(host, port, timeout)
    except Exception:
        return False
    try:
        writer.write(HTTPS_CONNECT_REQ)
        await writer.drain()
        data = await asyncio.wait_for(reader.read(64), timeout)
        if not data:
            return False
        status_line = data.split(b"\r\n", 1)[0]
        return b"200" in status_line
    except Exception:
        return False
    finally:
        writer.close()
        await writer.wait_closed()


def _split_host_port(proxy: str) -> tuple[str, int] | None:
    proxy = proxy.split("://")[-1]
    proxy = proxy.rsplit("@", 1)[-1]
    if ":" not in proxy:
        return None
    host, port_str = proxy.rsplit(":", 1)
    if not port_str.isdigit():
        return None
    return host, int(port_str)


async def classify_proxy(proxy: str, timeout: float = 2.0) -> str | None:
    parts = _split_host_port(proxy)
    if not parts:
        return None
    host, port = parts
    if await _try_socks5(host, port, timeout):
        return "socks5"
    if await _try_socks4(host, port, timeout):
        return "socks4"
    if await _try_http_get(host, port, timeout):
        return "http"
    if await _try_https_connect(host, port, timeout):
        return "https"
    return None


async def probe_proxies(proxies: List[str], concurrency: int = 10000, timeout: float = 2.0) -> dict[str, int]:
    sem = asyncio.Semaphore(concurrency)
    counts = {"socks5": 0, "socks4": 0, "http": 0, "https": 0}

    files = {
        "socks5": open("socks5.txt", "a", buffering=1),
        "socks4": open("socks4.txt", "a", buffering=1),
        "http": open("http.txt", "a", buffering=1),
        "https": open("https.txt", "a", buffering=1),
    }

    tested = 0

    async def worker(p: str) -> None:
        nonlocal tested
        async with sem:
            kind = await classify_proxy(p, timeout)
            if kind:
                files[kind].write(p + "\n")
                files[kind].flush()
                counts[kind] += 1
        tested += 1
        if tested % 10000 == 0:
            print(
                f"Tested {tested} proxies - socks5:{counts['socks5']} socks4:{counts['socks4']} http:{counts['http']} https:{counts['https']}"
            )

    tasks = [asyncio.create_task(worker(p)) for p in proxies]
    await asyncio.gather(*tasks)

    for fh in files.values():
        fh.close()

    return counts
