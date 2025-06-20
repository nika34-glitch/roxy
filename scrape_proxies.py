import asyncio
import logging
import re
import random
import ipaddress
import os
import json
import gzip
import ssl
import functools
import signal
import time
import argparse
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, AsyncGenerator, Any, Dict

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
    "MODE",
    "CRITICAL_MIN",
    "OVERALL_MIN",
    "WEIGHTS",
    "filter1",
    "scrape",
    "classify",
    "check_tls",
    "write_files",
    "print_stats",
    "install_asyncio_exception_handler",
    "main",
]

_log = logging.getLogger(__name__)


def install_asyncio_exception_handler(loop: asyncio.AbstractEventLoop | None = None) -> None:
    """Ignore benign connection errors from closed sockets on Windows."""
    if loop is None:
        loop = asyncio.get_event_loop()

    def handle(loop: asyncio.AbstractEventLoop, context: Dict[str, Any]) -> None:
        exc = context.get("exception")
        if isinstance(exc, (ConnectionResetError, ConnectionAbortedError)):
            _log.debug("ignored %s: %s", exc.__class__.__name__, exc)
            return
        loop.default_exception_handler(context)

    loop.set_exception_handler(handle)



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

TYPES = ["http", "https", "socks4", "socks5"]


@dataclass
class Stats:
    """In-memory counters for proxy scraping and testing."""

    total: int = 0
    passed_filter1: int = 0
    per_type: Dict[str, int] = field(default_factory=lambda: {t: 0 for t in TYPES})
    working: Dict[str, int] = field(default_factory=lambda: {t: 0 for t in TYPES})
    dead: Dict[str, int] = field(default_factory=lambda: {t: 0 for t in TYPES})
    start: float = field(default_factory=time.monotonic)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total": self.total,
            "passed_filter1": self.passed_filter1,
            "types": {
                t: {
                    "total": self.per_type[t],
                    "working": self.working[t],
                    "dead": self.dead[t],
                }
                for t in TYPES
            },
            "elapsed": time.monotonic() - self.start,
        }

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

IP_PORT_RE = re.compile(
    r"(?:\[(?P<ip6>[A-Fa-f0-9:]+)\]|(?P<ip4>(?:\d{1,3}\.){3}\d{1,3})):(?P<port>\d{1,5})"
)
REQUEST_TIMEOUT = 10



def extract_proxies_from_text(text: str) -> List[str]:
    """Return list of ``ip:port`` strings found in *text*.

    This also handles simple JSON structures containing ``ip`` and ``port``
    fields.
    """

    proxies: List[str] = []
    try:
        data = json.loads(text)
    except Exception:
        data = None

    def _from_json(obj: Any) -> None:
        if isinstance(obj, dict):
            ip = obj.get("ip") or obj.get("host")
            if not ip and isinstance(obj.get("export_address"), list):
                ip = obj["export_address"][0]
            port = obj.get("port")
            if ip and port:
                proxies.append(f"{ip}:{port}")
            for v in obj.values():
                _from_json(v)
        elif isinstance(obj, list):
            for item in obj:
                _from_json(item)

    if data is not None:
        _from_json(data)

    if not proxies:
        for m in IP_PORT_RE.finditer(text):
            host = m.group("ip6") or m.group("ip4")
            port = m.group("port")
            proxies.append(f"{host}:{port}")

    return proxies

from contextlib import asynccontextmanager


@asynccontextmanager
async def get_aiohttp_session() -> AsyncGenerator[Any, None]:
    """Yield a temporary ``aiohttp.ClientSession`` and close it afterwards."""
    try:
        import aiohttp  # type: ignore
    except Exception as exc:  # pragma: no cover - optional dependency
        raise RuntimeError("aiohttp required") from exc
    session = aiohttp.ClientSession()
    try:
        yield session
    finally:
        await session.close()

async def fetch_proxxy_sources() -> AsyncGenerator[List[str], None]:
    sources = PROXXY_SOURCES
    urls = [u for lst in sources.values() for u in lst]
    async with get_aiohttp_session() as session:
        tasks = {
            asyncio.create_task(session.get(url, timeout=REQUEST_TIMEOUT)): url
            for url in urls
        }
        batch: List[str] = []
        seen: set[str] = set()
        for task in asyncio.as_completed(tasks):
            url = tasks[task]
            try:
                resp = await task
                text_parts: List[str] = []
                async for raw_line in resp.content:
                    text_parts.append(raw_line.decode(errors="ignore"))
                proxies = extract_proxies_from_text("\n".join(text_parts))
                for p in proxies:
                    if p in seen:
                        continue
                    seen.add(p)
                    batch.append(p)
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
    seen: dict[str, set[str]] = {k: set() for k in PROXXY_SOURCES}
    async with get_aiohttp_session() as session:
        for proto, urls in PROXXY_SOURCES.items():
            for url in urls:
                try:
                    resp = await session.get(url, timeout=REQUEST_TIMEOUT)
                    text_parts: List[str] = []
                    async for raw_line in resp.content:
                        text_parts.append(raw_line.decode(errors="ignore"))
                    proxies = extract_proxies_from_text("\n".join(text_parts))
                    for p in proxies:
                        if p in seen[proto]:
                            continue
                        seen[proto].add(p)
                        result[proto].append(p)
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
        patterns = [
            r"(?:(?:http|https|socks[45])://)?(?P<ip>\d{1,3}(?:\.\d{1,3}){3}):(?P<port>\d+)(?:/)?",
            r"(?:(?:http|https|socks[45])://)?\[(?P<ip>[A-F0-9:]+)\]:(?P<port>\d+)(?:/)?",
            r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})[.;-](?P<port>\d+)",
            r"\[(?P<ip>[A-F0-9:]+)\][.;-](?P<port>\d+)",
            r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+(?P<port>\d+)",
            r"\[(?P<ip>[A-F0-9:]+)\]\s+(?P<port>\d+)",
            r"(?:(?:http|https|socks[45])://)?(?P<ip>[A-F0-9]*:[A-F0-9:]+):(?P<port>\d+)",
            r"(?P<ip>[A-F0-9]*:[A-F0-9:]+)[.;-](?P<port>\d+)",
            r'"(?P<ip>\d{1,3}(?:\.\d{1,3}){3}):(?P<port>\d+)"',
            r"(?:(?:http|https|socks[45])://)?(?P<ip>\d{1,3}(?:\.\d{1,3}){3}):(?P<port>\d+)/",
        ]
        found: List[str] = []
        for pat in patterns:
            for ip, port in re.findall(pat, html_content, flags=re.I):
                found.append(f"{ip}:{port}")
        # remove duplicates while preserving order
        return list(dict.fromkeys(found))

    def save_proxies(self, protocol: str, proxies: List[str]) -> None:
        os.makedirs("output", exist_ok=True)
        file_path = f"output/{protocol}.txt"
        with open(file_path, "a") as f:
            for p in proxies:
                f.write(p + "\n")

# ---------------------------------------------------------------------------
# Scoring helpers used by filter1
# ---------------------------------------------------------------------------

# Keep in-memory blacklist loaded from optional file
BLACKLIST: set[str] = set()


async def load_blacklists(path: str | None = None) -> None:
    """Load blacklist entries from *path* into ``BLACKLIST`` if available."""

    global BLACKLIST
    BLACKLIST.clear()
    file_path = path or os.getenv(
        "BLACKLIST_PATH",
        str(Path(__file__).resolve().parent / "data" / "blacklist.txt"),
    )
    if os.path.exists(file_path):
        try:
            with open(file_path, "r") as fh:
                for line in fh:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        BLACKLIST.add(line)
        except Exception as exc:  # pragma: no cover - optional file errors
            _log.error("error loading blacklist %s: %s", file_path, exc)


async def _score_single_proxy(
    p: str, ctx: ssl.SSLContext, timeout: float, return_all: bool = False
) -> tuple[str, int, dict[str, int]] | None:
    """Return proxy score and component parts.

    This simplified scorer only checks blacklist membership and TLS reachability.
    ``ip_rep`` is treated as a constant weight for all proxies.
    """

    proto, host, port_str = p.split(":", 2)
    parts: dict[str, int] = {}

    if host in BLACKLIST:
        parts["critical"] = 0
        return (p, 0, parts) if return_all else None

    tls_ok = await check_tls(f"{host}:{port_str}", proto, timeout)
    critical = WEIGHTS.get("tls_reach", 0) if tls_ok else 0
    parts["critical"] = critical

    score = critical + WEIGHTS.get("ip_rep", 0)

    return (p, score, parts) if return_all else (p, score, parts)


async def filter1(
    proxies: List[str], timeout: float = 5.0, concurrency: int = 5000
) -> List[str]:
    """Filter *proxies* using TLS reachability and scoring thresholds."""

    proxies = [
        p
        for p in proxies
        if p.split(":", 1)[0].lower() in {"http", "https", "socks4", "socks5"}
    ]
    if not proxies:
        return []

    await load_blacklists()

    ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2

    sem = asyncio.Semaphore(concurrency)
    good: List[str] = []

    async def worker(p: str) -> None:
        async with sem:
            res = await _score_single_proxy(p, ctx, timeout, return_all=True)
        if res is None:
            return
        norm, score, parts = res
        crit = parts.get("critical", 0)
        if score >= OVERALL_MIN and crit >= CRITICAL_MIN:
            good.append(norm)
        elif MODE == "lenient" and 500 <= score < 600:
            # Quarantine feature from former filter_p2 (not returned)
            pass

    tasks = [asyncio.create_task(worker(p)) for p in proxies]
    for t in asyncio.as_completed(tasks):
        await t
    return good

# ---------------------------------------------------------------------------
# Minimal async fetcher using HTTP sources
# ---------------------------------------------------------------------------
async def fetch_proxies(types: List[str] | None = None, limit: int = 100) -> List[str]:
    if types is None:
        types = ["HTTP", "HTTPS"]
    collected: List[str] = []
    proxies_by_type = await collect_proxies_by_type()
    for proto in types:
        for proxy in proxies_by_type.get(proto.upper(), []):
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


async def _safe_close(writer: asyncio.StreamWriter) -> None:
    writer.close()
    try:
        await writer.wait_closed()
    except ConnectionError:
        pass
    except Exception as exc:  # pragma: no cover - unexpected close issue
        _log.debug("ignored close error: %s", exc)


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
        await _safe_close(writer)


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
        await _safe_close(writer)


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
        await _safe_close(writer)


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
        await _safe_close(writer)


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


def _check_tls_sync(proxy: str, ptype: str, timeout: float, host: str, port: int) -> bool:
    if ptype == "direct":
        import socket
        try:
            sock = socket.create_connection((host, port), timeout=timeout)
        except Exception:
            return False
    else:
        try:
            import socks  # type: ignore
        except Exception as exc:  # pragma: no cover - missing dependency
            raise RuntimeError("PySocks required") from exc

        addr = _split_host_port(proxy)
        if not addr:
            return False
        phost, pport = addr
        sock = socks.socksocket()
        if ptype == "socks5":
            sock.set_proxy(socks.SOCKS5, phost, pport)
        elif ptype == "socks4":
            sock.set_proxy(socks.SOCKS4, phost, pport)
        elif ptype in {"http", "https"}:
            sock.set_proxy(socks.HTTP, phost, pport)
        sock.settimeout(timeout)
        try:
            sock.connect((host, port))
        except Exception:
            try:
                sock.close()
            finally:
                return False
    sock.settimeout(timeout)
    try:
        if ptype == "direct":
            pass  # connection already established
        else:
            pass  # connection done above
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        wrapped = ctx.wrap_socket(sock, server_hostname=host)
        wrapped.settimeout(timeout)
        wrapped.do_handshake()
        wrapped.close()
        return True
    except Exception:
        try:
            sock.close()
        finally:
            return False


async def check_tls(
    proxy: str,
    ptype: str,
    timeout: float = 5.0,
    target_host: str = "pop.libero.it",
    target_port: int = 995,
) -> bool:
    """Return True if TLS handshake to target succeeds via *proxy*."""

    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(
        None, _check_tls_sync, proxy, ptype, timeout, target_host, target_port
    )


async def scrape() -> List[str]:
    """Collect proxies from all configured sources."""

    data = await collect_proxies_by_type()
    proxies: List[str] = []
    seen: set[str] = set()
    for lst in data.values():
        for p in lst:
            if p in seen:
                continue
            seen.add(p)
            proxies.append(p)
    return proxies


async def classify(proxies: List[str], timeout: float = 2.0) -> List[str]:
    """Return normalized proxies with detected protocol."""

    result: List[str] = []
    seen: set[str] = set()
    sem = asyncio.Semaphore(1000)

    async def worker(p: str) -> None:
        async with sem:
            kind = await classify_proxy(p, timeout)
        if kind:
            norm = f"{kind}:{p}"
            if norm in seen:
                return
            seen.add(norm)
            result.append(norm)

    tasks = [asyncio.create_task(worker(p)) for p in proxies]
    for t in asyncio.as_completed(tasks):
        await t
    return result


def write_files(files: Dict[str, Any]) -> None:
    for fh in files.values():
        fh.flush()
        fh.close()


async def print_stats(stats: Stats, path: Path) -> None:
    summary = [f"Total: {stats.total}"]
    for t in TYPES:
        summary.append(
            f"{t}: {stats.per_type[t]} (" \
            f"{stats.working[t]} working / {stats.dead[t]} dead)"
        )
    summary.append(f"Passed filter1: {stats.passed_filter1}")
    print("[Stats] " + " | ".join(summary))
    with open(path / "stats.json", "w") as fh:
        json.dump(stats.to_dict(), fh, indent=2)


async def main(argv: List[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Proxy scraper")
    parser.add_argument("--timeout", type=float, default=5.0, help="TLS handshake timeout")
    parser.add_argument("--concurrency", type=int, default=5000, help="Maximum simultaneous checks")
    parser.add_argument("--stats-interval", type=float, default=1.0, help="Seconds between stats output")
    parser.add_argument("--output-dir", type=str, default=".", help="Directory for output files")
    args = parser.parse_args(argv)

    install_asyncio_exception_handler()

    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    files = {t: open(out_dir / f"{t}.txt", "a", buffering=1) for t in TYPES}
    working_files = {t: open(out_dir / f"{t}_working.txt", "a", buffering=1) for t in TYPES}

    stats = Stats()
    stop = False

    def _sigint(*_: Any) -> None:
        nonlocal stop
        stop = True

    signal.signal(signal.SIGINT, _sigint)

    proxies = await scrape()

    queue: asyncio.Queue[str] = asyncio.Queue()
    for p in proxies:
        queue.put_nowait(p)

    sem = asyncio.Semaphore(args.concurrency)

    async def worker() -> None:
        while not stop:
            try:
                proxy = queue.get_nowait()
            except asyncio.QueueEmpty:
                return

            stats.total += 1
            async with sem:
                kind = await classify_proxy(proxy, timeout=2.0)
            if not kind:
                continue
            stats.per_type[kind] += 1
            files[kind].write(f"{proxy}\n")
            ok = await check_tls(proxy, kind, args.timeout)
            if ok:
                stats.working[kind] += 1
                stats.passed_filter1 += 1
                working_files[kind].write(f"{proxy}\n")
            else:
                stats.dead[kind] += 1

    workers = [asyncio.create_task(worker()) for _ in range(args.concurrency)]

    async def stats_loop() -> None:
        while any(not w.done() for w in workers):
            await asyncio.sleep(args.stats_interval)
            await print_stats(stats, out_dir)
        await print_stats(stats, out_dir)

    stats_task = asyncio.create_task(stats_loop())
    try:
        await asyncio.gather(stats_task, *workers)
    except asyncio.CancelledError:
        for w in workers:
            w.cancel()
        stats_task.cancel()
        await asyncio.gather(stats_task, *workers, return_exceptions=True)
        raise
    finally:
        write_files(files)
        write_files(working_files)

