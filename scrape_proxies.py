import requests
import time
import threading
import random
import re
import base64
import asyncio
import os
import socket
import struct
import json
import importlib.util
from pathlib import Path
from typing import AsyncGenerator, List
from concurrent.futures import ThreadPoolExecutor
import gzip
import orjson
import regex
import logging
import ipaddress
import itertools
import aiofiles

from proxyhub import SOURCE_LIST, fetch_source

import aiohttp
from bs4 import BeautifulSoup

REQUEST_TIMEOUT = int(os.getenv("REQUEST_TIMEOUT", "10"))

MTPROTO_URL = "https://mtpro.xyz/api/?type=mtproto"
SOCKS_URL = "https://mtpro.xyz/api/?type=socks"
OUTPUT_DIR = os.getenv("OUTPUT_DIR", ".")
OUTPUT_FILE = os.getenv("OUTPUT_FILE", "proxies.txt")
OUTPUT_COMPRESSED = os.getenv("OUTPUT_COMPRESSED", "0") == "1"
if OUTPUT_COMPRESSED and not OUTPUT_FILE.endswith(".gz"):
    OUTPUT_FILE += ".gz"

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(level=LOG_LEVEL, format="%(asctime)s [%(levelname)s] %(message)s")

PROXXY_SOURCES_FILE = os.path.join(
    os.path.dirname(__file__), "vendor", "proXXy", "proxy_sources.json"
)

# ProxyHub async scraping configuration
PROXYHUB_INTERVAL = 300.0  # seconds between ProxyHub runs
PROXYHUB_CONCURRENCY = int(os.getenv("PROXYHUB_CONCURRENCY", "20"))
BLOODY_INTERVAL = 300  # seconds between Bloody-Proxy-Scraper runs
MAX_PROXY_SET_SIZE = int(os.getenv("MAX_PROXY_SET_SIZE", "100000"))

MT_INTERVAL = 1  # seconds between mtpro.xyz polls
PASTE_INTERVAL = 60  # seconds between paste feed checks
FEED_DELAY_RANGE = (5, 10)  # delay between individual feed requests

PASTE_FEEDS = [
    "https://pastebin.com/feed",
    "https://ghostbin.com/recent",
    "https://paste.ee/rss",
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36",
]

PROXY_RE = regex.compile(r"((?:\d{1,3}\.){3}\d{1,3}):(\d{1,5})")
IP_PORT_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}:\d+$")
PROTO_PARAM_RE = re.compile(r"protocol=([^&]+)")
FREE_CZ_BASE64_RE = re.compile(r'Base64.decode\("([^"]+)"\)')
FREE_CZ_PAGE_RE = re.compile(r"/en/proxylist/main/(\d+)")

# IRC collection configuration
IRC_SERVERS = [
    "irc.undernet.org",
    "irc.rizon.net",
    "irc.libera.chat",
    "irc.abjects.net",
    "irc.efnet.org",
    "irc.darkscience.net",
    "irc.dal.net",
]

IRC_CHANNELS = [
    "#proxy",
    "#proxylist",
    "#proxies",
    "#proxyleaks",
    "#socks",
    "#socks4",
    "#socks5",
    "#leech",
    "#leechers",
    "#0day",
    "#darkweb",
    "#darkproxies",
    "#http",
    "#socks_proxy",
    "#proxyfeeds",
    "#botnet",
    "#scraperbots",
    "#anonproxies",
    "#blackhat",
    "#hackers",
    "#freeland",
    "#datadump",
    "#dump",
    "#proxy-dump",
    "#proxy_bots",
    "#proxy_scrape",
    "#dumpville",
    "#proxy_zone",
    "#openproxies",
    "#publicproxies",
    "#proxyhunt",
    "#torleaks",
    "#rawfeeds",
    "#autoproxy",
    "#scanfeeds",
    "#mirrors",
    "#ipfeeds",
    "#portscanners",
    "#hostlist",
    "#proxylogs",
]

# DHT crawling configuration
BOOTSTRAP_NODES = [
    ("router.bittorrent.com", 6881),
    ("dht.transmissionbt.com", 6881),
]
MAX_DHT_CONCURRENCY = int(os.getenv("MAX_DHT_CONCURRENCY", "50"))
MAX_DHT_WORKERS = int(os.getenv("MAX_DHT_WORKERS", "10"))
PROXY_PORTS = {8080, 3128, 1080, 9050, 8000, 8081, 8888}
DHT_LOG_EVERY = 100  # log progress every N visited nodes

# Tor relay crawling configuration
ONIONOO_URL = "https://onionoo.torproject.org/details"
TOR_INTERVAL = 3600  # seconds between Tor relay list updates

# Additional HTTP API backends
API_INTERVAL = 0.3  # delay between individual API requests
PROXYSCRAPE_HTTP_URL = "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=10000&country=all&ssl=no&anonymity=all"
PROXYSCRAPE_SOCKS4_URL = "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks4&timeout=10000&country=all"
PROXYSCRAPE_SOCKS5_URL = "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks5&timeout=10000&country=all"
GIMMEPROXY_URL = "https://gimmeproxy.com/api/getProxy"
PUBPROXY_URL = "http://pubproxy.com/api/proxy"
PROXYKINGDOM_URL = "https://api.proxykingdom.com/proxy?token=xN9IoZDLnMzUC0"
GEONODE_URL = (
    "https://proxylist.geonode.com/api/proxy-list"
    "?limit=500&page=4&sort_by=lastChecked&sort_type=desc"
)
GEONODE_INTERVAL = 5  # seconds between geonode API requests

# GatherProxy scraping configuration
GATHER_PROXY_URI = "http://www.gatherproxy.com/proxylist/anonymity/"
GATHER_PROXY_INTERVAL = 600  # seconds between full GatherProxy cycles
GATHER_PROXY_CONCURRENCY = 5  # how many pages to fetch in parallel
GATHER_PROXY_MIN_UPTIME = 0  # Uptime filter

# ProxyScraper integration settings
PS_SCRAPER_SOURCES = [
    "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=10000&country=all",
    "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks4&timeout=10000",
    "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks5&timeout=10000",
    # add any other ProxyScraper endpoints here
]
# seconds between each ProxyScraper fetch cycle
PS_INTERVAL = 30
# how many sources to fetch in parallel
PS_CONCURRENT_REQUESTS = 5
# Increase PS_CONCURRENT_REQUESTS or lower PS_INTERVAL to speed up scraping,
# or decrease them to reduce load.

SHARED_THREAD_POOL = ThreadPoolExecutor(max_workers=PS_CONCURRENT_REQUESTS)

# ProxySpace backend configuration
PROXYSPACE_HTTP_URL = "https://proxyspace.pro/http.txt"
PROXYSPACE_HTTPS_URL = "https://proxyspace.pro/https.txt"
PROXYSPACE_SOCKS4_URL = "https://proxyspace.pro/socks4.txt"
PROXYSPACE_SOCKS5_URL = "https://proxyspace.pro/socks5.txt"
# fetch new lists roughly every 20 minutes
PROXYSPACE_INTERVAL = 1200

# dpangestuw Free-Proxy GitHub lists
FREEPROXY_HTTP_URL = "https://raw.githubusercontent.com/dpangestuw/Free-Proxy/refs/heads/main/http_proxies.txt"
FREEPROXY_SOCKS4_URL = "https://raw.githubusercontent.com/dpangestuw/Free-Proxy/refs/heads/main/socks4_proxies.txt"
FREEPROXY_SOCKS5_URL = "https://raw.githubusercontent.com/dpangestuw/Free-Proxy/refs/heads/main/socks5_proxies.txt"
FREEPROXY_INTERVAL = 120  # fetch every 2 minutes
# aggregated list updated every 5 minutes
FREEPROXY_ALL_URL = "https://raw.githubusercontent.com/dpangestuw/Free-Proxy/refs/heads/main/All_proxies.txt"
FREEPROXY_ALL_INTERVAL = 300

# Fresh Proxy List (vakhov.github.io)
FRESHPROXY_HTTP_URL = "https://vakhov.github.io/fresh-proxy-list/http.txt"
FRESHPROXY_HTTPS_URL = "https://vakhov.github.io/fresh-proxy-list/https.txt"
FRESHPROXY_SOCKS4_URL = "https://vakhov.github.io/fresh-proxy-list/socks4.txt"
FRESHPROXY_SOCKS5_URL = "https://vakhov.github.io/fresh-proxy-list/socks5.txt"
FRESHPROXY_INTERVAL = 300  # fetch every 5 minutes

# KangProxy aggregated lists
KANGPROXY_OLD_URL = "https://raw.githubusercontent.com/officialputuid/KangProxy/KangProxy/xResults/old-data/RAW.txt"
KANGPROXY_URL = "https://raw.githubusercontent.com/officialputuid/KangProxy/KangProxy/xResults/RAW.txt"
KANGPROXY_INTERVAL = 14400  # fetch every 4 hours

# Proxifly GitHub proxy lists
PROXIFLY_HTTP_URL = "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/http/data.txt"
PROXIFLY_SOCKS4_URL = "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/socks4/data.txt"
PROXIFLY_SOCKS5_URL = "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/socks5/data.txt"
PROXIFLY_INTERVAL = 300  # fetch every 5 minutes

# Free proxy list websites
PROXY_LIST_SITES = [
    ("https://free-proxy-list.net/", "http"),
    ("https://us-proxy.org/", "http"),
    ("https://sslproxies.org/", "http"),
    ("https://socks-proxy.net/", "socks5"),
]
PROXY_LIST_INTERVAL = 600  # sites update roughly every 10 minutes

# spys.me proxy lists
SPYS_HTTP_URL = "https://spys.me/proxy.txt"
SPYS_SOCKS_URL = "https://spys.me/socks.txt"
SPYS_INTERVAL = 300  # fetch every 5 minutes

# ProxyBros free proxy list
PROXYBROS_URL = "https://proxybros.com/free-proxy-list/"
PROXYBROS_INTERVAL = 600  # fetch every 10 minutes

# openproxylist.xyz raw lists
OPENPROXYLIST_INTERVAL = 900  # seconds between full cycles
OPENPROXYLIST_CONCURRENCY = 4  # how many lists to fetch in parallel
OPENPROXYLIST_ENDPOINTS = [
    "https://openproxylist.xyz/http.txt",
    "https://openproxylist.xyz/https.txt",
    "https://openproxylist.xyz/socks4.txt",
    "https://openproxylist.xyz/socks5.txt",
]

SCRAPERS = {
    "mtpro": MT_INTERVAL,
    "paste": PASTE_INTERVAL,
    "freeproxy_world": 20,
    "free_proxy_cz": 20,
    "tor": TOR_INTERVAL,
    "proxyscrape": API_INTERVAL,
    "gimmeproxy": API_INTERVAL,
    "pubproxy": API_INTERVAL,
    "proxykingdom": API_INTERVAL,
    "geonode": GEONODE_INTERVAL,
    "proxyspace": PROXYSPACE_INTERVAL,
    "proxy_list_sites": PROXY_LIST_INTERVAL,
    "proxy_list_download": API_INTERVAL,
    "freeproxy": FREEPROXY_INTERVAL,
    "freshproxy": FRESHPROXY_INTERVAL,
    "proxifly": PROXIFLY_INTERVAL,
    "freeproxy_all": FREEPROXY_ALL_INTERVAL,
    "kangproxy": KANGPROXY_INTERVAL,
    "spys": SPYS_INTERVAL,
    "proxybros": PROXYBROS_INTERVAL,
    "openproxylist": OPENPROXYLIST_INTERVAL,
    "gatherproxy": GATHER_PROXY_INTERVAL,
    "bloody": BLOODY_INTERVAL,
    "proxxy": 300,
}

# Load optional configuration overrides
CONFIG_FILE = os.getenv("CONFIG_FILE", "config.json")
if os.path.exists(CONFIG_FILE):
    try:
        with open(CONFIG_FILE) as f:
            cfg = json.load(f)
        for k, v in cfg.items():
            if k.isupper():
                globals()[k] = v
    except Exception as exc:
        logging.error("Error loading config %s: %s", CONFIG_FILE, exc)

requests_session = requests.Session()
aiohttp_session: aiohttp.ClientSession | None = None
httpx_client = None
USE_HTTP2 = os.getenv("USE_HTTP2", "0") == "1"

proxy_set: set[str] = set()
proxy_lock = asyncio.Lock()
new_entries: list[str] = []
write_event = asyncio.Event()
lock = threading.Lock()


PROTOCOL_RE = re.compile(r"^(https?|socks4|socks5)$", re.I)


def normalize_proxy(entry: str) -> str | None:
    """Return proxy as proto:ip:port if valid, else None."""
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


TEST_PROXIES = os.getenv("TEST_PROXIES", "0") == "1"
TEST_URLS = os.getenv("TEST_URLS")
if TEST_URLS:
    TEST_URLS = [u.strip() for u in TEST_URLS.split(",") if u.strip()]
else:
    TEST_URLS = [
        "http://example.com",
        "https://httpbin.org/get",
        "http://neverssl.com",
    ]
_test_url_cycle = itertools.cycle(TEST_URLS)
TEST_URL = TEST_URLS[0]
POOL_LIMIT = int(os.getenv("POOL_LIMIT", "50"))
MIN_POOL_LIMIT = 5
MAX_POOL_LIMIT = int(os.getenv("MAX_POOL_LIMIT", str((os.cpu_count() or 1) * 20)))
CHECK_CONNECT_TIMEOUT = float(os.getenv("CHECK_CONNECT_TIMEOUT", "3"))
CHECK_READ_TIMEOUT = float(os.getenv("CHECK_READ_TIMEOUT", "3"))
PROXY_CACHE_TTL = int(os.getenv("PROXY_CACHE_TTL", "300"))
KNOWN_GOOD_TTL = int(os.getenv("KNOWN_GOOD_TTL", "3600"))
CHECK_CHUNK_SIZE = int(os.getenv("CHECK_CHUNK_SIZE", "200"))
MAX_RETRIES = int(os.getenv("CHECK_MAX_RETRIES", "2"))

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/115.0",
]

proxy_check_time: dict[str, float] = {}
proxy_latency: dict[str, float] = {}


def adjust_pool_limit(success_rate: float) -> None:
    """Adjust concurrency based on success rate."""
    global POOL_LIMIT, aiohttp_session
    if success_rate < 0.3 and POOL_LIMIT > MIN_POOL_LIMIT:
        POOL_LIMIT = max(MIN_POOL_LIMIT, int(POOL_LIMIT * 0.8))
    elif success_rate > 0.7 and POOL_LIMIT < MAX_POOL_LIMIT:
        POOL_LIMIT = min(MAX_POOL_LIMIT, POOL_LIMIT + 5)
    if aiohttp_session is not None:
        aiohttp_session.connector.limit = POOL_LIMIT


async def filter_working(proxies: list[str]) -> list[str]:
    """Return only proxies that successfully perform a simple request."""
    if not TEST_PROXIES:
        return proxies

    results: list[str] = []
    for i in range(0, len(proxies), CHECK_CHUNK_SIZE):
        chunk = proxies[i : i + CHECK_CHUNK_SIZE]
        results.extend(await _filter_chunk(chunk))
    return results


async def _filter_p1_batch(proxies: list[str], service: str = "pop3") -> list[str]:
    """Run ``filter_p1`` on a list of proxies asynchronously."""

    sem = asyncio.Semaphore(POOL_LIMIT)

    def to_url(p: str) -> str:
        proto, ip, port = p.split(":")
        return f"{proto}://{ip}:{port}"

    async def check(p: str) -> str | None:
        async with sem:
            ok = await asyncio.to_thread(filter_p1, to_url(p), service)
            return p if ok else None

    tasks = [asyncio.create_task(check(p)) for p in proxies]
    gathered = await asyncio.gather(*tasks, return_exceptions=True)
    results: list[str] = []
    for res in gathered:
        if isinstance(res, Exception):
            continue
        if res:
            results.append(res)
    return results


async def _filter_chunk(proxies: list[str]) -> list[str]:
    session = await get_aiohttp_session()
    sem = asyncio.Semaphore(POOL_LIMIT)
    timeout = aiohttp.ClientTimeout(
        connect=CHECK_CONNECT_TIMEOUT,
        sock_read=CHECK_READ_TIMEOUT,
    )

    async def socks_handshake(ip: str, port: int, proto: str) -> bool:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=CHECK_CONNECT_TIMEOUT
            )
            if proto == "socks5":
                writer.write(b"\x05\x01\x00")
                await writer.drain()
                resp = await asyncio.wait_for(reader.readexactly(2), timeout=1)
                if resp != b"\x05\x00":
                    writer.close()
                    await writer.wait_closed()
                    return False
                req = b"\x05\x01\x00\x03\x0bexample.com\x00\x50"
                writer.write(req)
                await writer.drain()
                resp = await asyncio.wait_for(reader.readexactly(10), timeout=1)
                writer.close()
                await writer.wait_closed()
                return resp[1] == 0x00
            else:  # socks4
                req = b"\x04\x01\x00\x50\x00\x00\x00\x01\x00"
                writer.write(req)
                await writer.drain()
                resp = await asyncio.wait_for(reader.readexactly(8), timeout=1)
                writer.close()
                await writer.wait_closed()
                return resp[1] == 0x5A
        except Exception:
            return False

    async def check(p: str) -> str | None:
        proto, ip, port = p.split(":")
        ttl = KNOWN_GOOD_TTL if p in proxy_latency else PROXY_CACHE_TTL
        if p in proxy_check_time and time.monotonic() - proxy_check_time[p] < ttl:
            return p

        for attempt in range(MAX_RETRIES + 1):
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, int(port)),
                    timeout=CHECK_CONNECT_TIMEOUT,
                )
                writer.close()
                await writer.wait_closed()
            except Exception:
                if attempt >= MAX_RETRIES:
                    return None
                await asyncio.sleep(2 ** attempt)
                continue

            start = time.perf_counter()
            try:
                async with sem:
                    if proto.startswith("socks"):
                        if not await socks_handshake(ip, int(port), proto):
                            raise RuntimeError("socks handshake failed")
                    else:
                        proxy_url = f"{proto}://{ip}:{port}"
                        headers = {"User-Agent": random.choice(USER_AGENTS)}
                        async with session.head(
                            next(_test_url_cycle),
                            proxy=proxy_url,
                            timeout=timeout,
                            headers=headers,
                        ):
                            pass
                latency = time.perf_counter() - start
                proxy_latency[p] = latency
                proxy_check_time[p] = time.monotonic()
                return p
            except Exception:
                if attempt >= MAX_RETRIES:
                    return None
                await asyncio.sleep(2 ** attempt)
        return None

    tasks = [asyncio.create_task(check(p)) for p in proxies]
    gathered = await asyncio.gather(*tasks, return_exceptions=True)
    results: list[str] = []
    successes = 0
    for res in gathered:
        if isinstance(res, Exception):
            continue
        if res:
            successes += 1
            results.append(res)

    success_rate = successes / len(proxies) if proxies else 0
    adjust_pool_limit(success_rate)
    return results


async def quick_validate(proxies: list[str]) -> list[str]:
    """Check that proxy ports are reachable."""
    sem = asyncio.Semaphore(POOL_LIMIT)

    async def check(p: str) -> str | None:
        try:
            _, ip, port = p.split(":")
            async with sem:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, int(port)),
                    timeout=1,
                )
                writer.close()
                await writer.wait_closed()
            return p
        except Exception:
            return None

    tasks = [asyncio.create_task(check(p)) for p in proxies]
    gathered = await asyncio.gather(*tasks, return_exceptions=True)
    results: list[str] = []
    successes = 0
    for res in gathered:
        if isinstance(res, Exception):
            continue
        if res:
            successes += 1
            results.append(res)
    success_rate = successes / len(proxies) if proxies else 0
    adjust_pool_limit(success_rate)
    return results


def _output_path(proto: str) -> str:
    base = f"{proto}_" + os.path.basename(OUTPUT_FILE)
    return os.path.join(OUTPUT_DIR, base)


async def write_entries(entries: list[str]) -> None:
    proto_groups: dict[str, list[str]] = {}
    for p in entries:
        proto = p.split(":", 1)[0]
        proto_groups.setdefault(proto, []).append(p)

    for proto, items in proto_groups.items():
        path = _output_path(proto)
        mode = "at" if OUTPUT_COMPRESSED else "a"
        if OUTPUT_COMPRESSED:
            await asyncio.to_thread(_write_gzip, path, items, mode)
        else:
            async with aiofiles.open(path, mode) as f:
                for line in items:
                    await f.write(line + "\n")


def _write_gzip(path: str, items: list[str], mode: str) -> None:
    with gzip.open(path, mode) as f:
        for line in items:
            f.write((line + "\n").encode())


def filter_p1(proxy_url: str, service_name: str) -> bool:
    """Validate TCP and TLS connectivity for a service via optional proxy.

    Parameters
    ----------
    proxy_url: str
        Proxy URL like ``socks5://user:pass@1.2.3.4:1080`` or ``"none"`` for
        direct connection.
    service_name: str
        Currently only ``"pop3"`` is supported.

    Returns
    -------
    bool
        ``True`` on successful TCP and TLS handshake, ``False`` otherwise.
    """

    if service_name.lower() != "pop3":
        print(f"Unsupported service: {service_name}")
        return False

    host, port = "pop.libero.it", 995

    original_socket = socket.socket
    if proxy_url.lower() != "none":
        from urllib.parse import urlparse
        import socks

        parsed = urlparse(proxy_url)
        scheme = (parsed.scheme or "socks5").lower()
        proxy_host = parsed.hostname
        proxy_port = parsed.port
        username = parsed.username
        password = parsed.password

        if not proxy_host or not proxy_port:
            print("Invalid proxy URL")
            return False

        if scheme.startswith("socks5"):
            proxy_type = socks.SOCKS5
        elif scheme.startswith("socks4"):
            proxy_type = socks.SOCKS4
        elif scheme in ("http", "https"):
            proxy_type = socks.HTTP
        else:
            print(f"Unsupported proxy scheme: {scheme}")
            return False

        socks.set_default_proxy(
            proxy_type, proxy_host, proxy_port, username=username, password=password
        )
        socket.socket = socks.socksocket

    try:
        sock = socket.create_connection((host, port), timeout=10)
        print("TCP OK")
    except Exception as exc:
        print(str(exc))
        socket.socket = original_socket
        return False

    try:
        ctx = ssl.create_default_context()
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        tls_sock = ctx.wrap_socket(sock, server_hostname=host)
        tls_version = tls_sock.version()
        cipher = tls_sock.cipher()[0]
        print(f"TLS OK: {tls_version}, {cipher}")
        tls_sock.close()
        result = True
    except Exception as exc:
        print(str(exc))
        result = False
    finally:
        socket.socket = original_socket

    return result



async def get_aiohttp_session() -> aiohttp.ClientSession:
    global aiohttp_session, httpx_client
    if USE_HTTP2:
        if httpx_client is None:
            try:
                import httpx
            except Exception as exc:
                logging.warning("httpx not available for HTTP/2: %s", exc)
            else:
                httpx_client = httpx.AsyncClient(http2=True)
        if httpx_client:
            return httpx_client
    if aiohttp_session is None:
        connector = aiohttp.TCPConnector(limit=POOL_LIMIT, ttl_dns_cache=60)
        default_timeout = aiohttp.ClientTimeout(
            connect=CHECK_CONNECT_TIMEOUT, sock_read=CHECK_READ_TIMEOUT
        )
        aiohttp_session = aiohttp.ClientSession(
            connector=connector, timeout=default_timeout
        )
    return aiohttp_session


async def add_proxies(proxies: List[str]) -> None:
    async with proxy_lock:
        added = False
        for raw in proxies:
            p = normalize_proxy(raw)
            if not p or p in proxy_set:
                continue
            proxy_set.add(p)
            new_entries.append(p)
            added = True
        if added:
            write_event.set()


def add_proxies_sync(proxies: List[str]) -> None:
    added = False
    with lock:
        for raw in proxies:
            p = normalize_proxy(raw)
            if not p or p in proxy_set:
                continue
            proxy_set.add(p)
            new_entries.append(p)
            added = True
    if added:
        write_event.set()


async def writer_loop() -> None:
    while True:
        await write_event.wait()
        await asyncio.sleep(1)
        write_event.clear()
        async with proxy_lock:
            if not new_entries:
                continue
            entries = list(new_entries)
            new_entries.clear()
        entries = await quick_validate(entries)
        entries = await _filter_p1_batch(entries)
        entries = await filter_working(entries)
        await write_entries(entries)
        if len(proxy_set) > MAX_PROXY_SET_SIZE:
            logging.info("Flushing proxy set to limit memory usage")
            proxy_set.clear()


async def fetch_json(url: str) -> dict:
    session = await get_aiohttp_session()
    async with session.get(url, timeout=REQUEST_TIMEOUT) as resp:
        resp.raise_for_status()
        data = await resp.read()
        return orjson.loads(data)


async def fetch_proxxy_sources() -> AsyncGenerator[List[str], None]:
    """Fetch all proxy sources defined by the proXXy project."""
    try:
        with open(PROXXY_SOURCES_FILE, "r") as f:
            sources = json.load(f)
    except Exception as exc:
        logging.error("Error loading %s: %s", PROXXY_SOURCES_FILE, exc)
        return

    urls = []
    for url_list in sources.values():
        urls.extend(url_list)

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
        except Exception as e:
            logging.error("proXXy source error %s: %s", url, e)
    if batch:
        yield batch


async def scrape_mt_proxies() -> None:
    proxies = []
    try:
        mt_list = await fetch_json(MTPROTO_URL)
        for item in mt_list:
            host = item.get("host")
            port = item.get("port")
            if host and port:
                proxies.append(f"{host}:{port}")
    except Exception as e:
        logging.error("Error fetching mtproto proxies: %s", e)
    try:
        socks_list = await fetch_json(SOCKS_URL)
        for item in socks_list:
            ip = item.get("ip")
            port = item.get("port")
            if ip and port:
                proxies.append(f"{ip}:{port}")
    except Exception as e:
        logging.error("Error fetching socks proxies: %s", e)

    if proxies:
        await add_proxies(proxies)


async def scrape_freeproxy_world() -> None:
    """Fetch all proxies listed on freeproxy.world."""
    base_url = "https://www.freeproxy.world/"
    proxies: list[str] = []
    try:
        text = await fetch_with_backoff(base_url)
        if not text:
            return
        soup = BeautifulSoup(text, "lxml")
        count_div = soup.select_one(".proxy_table_pages")
        total = int(count_div.get("data-counts", "0")) if count_div else 0
        pages = max(1, (total + 49) // 50)
        for page in range(1, pages + 1):
            try:
                page_text = await fetch_with_backoff(base_url + f"?page={page}")
                if not page_text:
                    break
                soup = BeautifulSoup(page_text, "lxml")
                for row in soup.select("tbody tr"):
                    cols = [td.get_text(strip=True) for td in row.find_all("td")]
                    if len(cols) >= 6 and cols[0] and cols[1].isdigit():
                        proto = cols[5].split()[0].lower()
                        proxies.append(f"{proto}:{cols[0]}:{cols[1]}")
            except Exception as e:
                logging.error("Error fetching freeproxy.world page %s: %s", page, e)
                break
    except Exception as e:
        logging.error("Error fetching freeproxy.world: %s", e)

    if proxies:
        await add_proxies(proxies)


def _parse_free_proxy_cz_page(soup: BeautifulSoup) -> list[str]:
    """Extract proxies from a free-proxy.cz page soup."""
    proxies: list[str] = []
    for row in soup.select("tbody tr"):
        script = row.find("script")
        if not script or not script.string:
            continue
        m = FREE_CZ_BASE64_RE.search(script.string)
        if not m:
            continue
        try:
            ip = base64.b64decode(m.group(1)).decode()
        except Exception:
            continue
        port_span = row.find("span", class_="fport")
        if not port_span:
            continue
        port = port_span.get_text(strip=True)
        proto_elem = row.find("small")
        proto = proto_elem.get_text(strip=True).lower() if proto_elem else "http"
        proxies.append(f"{proto}:{ip}:{port}")
    return proxies


async def scrape_free_proxy_cz() -> None:
    """Fetch proxies from http://free-proxy.cz/en/ across all pages."""
    base_url = "http://free-proxy.cz"
    proxies: list[str] = []
    pages = 1
    try:
        text = await fetch_with_backoff(f"{base_url}/en/")
        if not text:
            return
        soup = BeautifulSoup(text, "lxml")
        proxies.extend(_parse_free_proxy_cz_page(soup))
        links = soup.select('a[href^="/en/proxylist/main/"]')
        for a in links:
            m = FREE_CZ_PAGE_RE.search(a.get("href", ""))
            if m:
                pages = max(pages, int(m.group(1)))
        for page in range(2, pages + 1):
            try:
                url = f"{base_url}/en/proxylist/main/{page}"
                page_text = await fetch_with_backoff(url)
                if not page_text:
                    break
                soup = BeautifulSoup(page_text, "lxml")
                proxies.extend(_parse_free_proxy_cz_page(soup))
            except Exception as e:
                logging.error("Error fetching free-proxy.cz page %s: %s", page, e)
                break
    except Exception as e:
        logging.error("Error fetching free-proxy.cz: %s", e)

    if proxies:
        await add_proxies(proxies)


async def fetch_with_backoff(url: str, max_retries: int = 5) -> str:
    delay = 1
    session = await get_aiohttp_session()
    for _ in range(max_retries):
        try:
            headers = {"User-Agent": random.choice(USER_AGENTS)}
            if (
                USE_HTTP2
                and hasattr(session, "get")
                and not isinstance(session, aiohttp.ClientSession)
            ):
                resp = await session.get(url, headers=headers)
                resp.raise_for_status()
                return resp.text
            async with session.get(url, headers=headers, timeout=REQUEST_TIMEOUT) as resp:
                if resp.status >= 400:
                    raise aiohttp.ClientResponseError(
                        resp.request_info, resp.history, status=resp.status
                    )
                return await resp.text()
        except Exception:
            sleep_time = delay + random.uniform(0, 1)
            await asyncio.sleep(sleep_time)
            delay = min(delay * 2, 60)
    return ""


def extract_proxies(text: str) -> list[str]:
    found = []
    for m in PROXY_RE.finditer(text):
        ip = m.group(1)
        port = int(m.group(2))
        if not (1 <= port <= 65535):
            continue
        octets = ip.split(".")
        if any(not 0 <= int(o) <= 255 for o in octets):
            continue
        snippet = text[max(0, m.start() - 20) : m.end() + 20].lower()
        protocol = "socks5" if "socks5" in snippet else "http"
        found.append(f"{protocol}:{ip}:{port}")
    return found


async def monitor_paste_feeds() -> None:
    for feed in PASTE_FEEDS:
        text = await fetch_with_backoff(feed)
        if text:
            proxies = extract_proxies(text)
            await add_proxies(proxies)
        await asyncio.sleep(random.uniform(*FEED_DELAY_RANGE))


async def scrape_tor_relays() -> None:
    """Fetch relay descriptors from Onionoo and record their addresses."""
    try:
        data = await fetch_json(ONIONOO_URL)
    except Exception as e:
        logging.error("Error fetching Tor relays: %s", e)
        return

        proxies = []
        for relay in data.get("relays", []):
            for addr in relay.get("or_addresses", []):
                host_port = addr.split("?")[0]
                if ":" not in host_port:
                    continue
                host, port = host_port.rsplit(":", 1)
                if port.isdigit():
                    proxies.append(f"{host}:{port}")

    if proxies:
        await add_proxies(proxies)


async def scrape_proxyscrape() -> None:
    urls = [
        (PROXYSCRAPE_HTTP_URL, "http"),
        (PROXYSCRAPE_SOCKS4_URL, "socks4"),
        (PROXYSCRAPE_SOCKS5_URL, "socks5"),
    ]
    proxies = []
    for url, proto in urls:
        try:
            text = await fetch_with_backoff(url)
            for line in text.splitlines():
                line = line.strip()
                if line:
                    proxies.append(f"{proto}:{line}")
        except Exception as e:
            logging.error("Error fetching %s: %s", url, e)
        await asyncio.sleep(SCRAPERS["proxyscrape"])
    if proxies:
        await add_proxies(proxies)


def _ps_get(url: str) -> str:
    """Helper for ProxyScraper integration to fetch a URL with error logging."""
    try:
        resp = requests.get(url, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        return resp.text
    except Exception as exc:
        logging.error("ProxyScraper source error %s: %s", url, exc)
        return ""


def scrape_proxyscraper_sources(interval: int = PS_INTERVAL) -> None:
    """Continuously fetch proxies from ProxyScraper sources."""
    urls = list(PS_SCRAPER_SOURCES)
    batch = PS_CONCURRENT_REQUESTS
    while True:
        new_entries: list[str] = []
        for i in range(0, len(urls), batch):
            subset = urls[i : i + batch]
            texts = list(SHARED_THREAD_POOL.map(_ps_get, subset))
            for url, text in zip(subset, texts):
                proto_match = PROTO_PARAM_RE.search(url)
                proto = proto_match.group(1).lower() if proto_match else "http"
                for line in text.splitlines():
                    line = line.strip()
                    if IP_PORT_RE.match(line):
                        new_entries.append(f"{proto}:{line}")

        if new_entries:
            add_proxies_sync(new_entries)

        time.sleep(interval)


def download_proxy_list(urls: list[tuple[str, str]]) -> list[str]:
    """Download simple text proxy lists."""
    entries: list[str] = []
    for url, proto in urls:
        try:
            resp = requests.get(url, timeout=REQUEST_TIMEOUT)
            resp.raise_for_status()
            for line in resp.text.splitlines():
                line = line.strip()
                if not line:
                    continue
                if "://" in line:
                    _, line = line.split("://", 1)
                entries.append(f"{proto}:{line}")
        except Exception as exc:
            logging.error("Error fetching %s: %s", url, exc)
        time.sleep(1)
    return entries


async def scrape_gimmeproxy() -> None:
    try:
        text = await fetch_with_backoff(GIMMEPROXY_URL)
        if not text:
            return
        data = orjson.loads(text.encode())
        ip = data.get("ip")
        port = data.get("port")
        protocol = data.get("protocol")
        if ip and port and protocol:
            await add_proxies([f"{protocol.lower()}:{ip}:{port}"])
    except Exception as e:
        logging.error("Error fetching gimmeproxy: %s", e)


async def scrape_pubproxy() -> None:
    try:
        text = await fetch_with_backoff(PUBPROXY_URL)
        if not text:
            return
        data = orjson.loads(text.encode())
        items = data.get("data", [])
        if items:
            item = items[0]
            ip_port = item.get("ipPort")
            if ip_port and ":" in ip_port:
                ip, port = ip_port.split(":", 1)
            else:
                ip = item.get("ip")
                port = item.get("port")
            protocol = item.get("type", "http")
            if ip and port:
                await add_proxies([f"{protocol.lower()}:{ip}:{port}"])
    except Exception as e:
        logging.error("Error fetching pubproxy: %s", e)


async def scrape_proxykingdom() -> None:
    try:
        text = await fetch_with_backoff(PROXYKINGDOM_URL)
        if not text:
            return
        data = orjson.loads(text.encode())
        ip = data.get("address") or data.get("ip")
        port = data.get("port")
        protocol = data.get("protocol")
        if ip and port and protocol:
            await add_proxies([f"{protocol.lower()}:{ip}:{port}"])
    except Exception as e:
        logging.error("Error fetching proxykingdom: %s", e)


async def scrape_geonode() -> None:
    """Fetch proxies from the geonode API."""
    proxies = []
    try:
        data = await fetch_json(GEONODE_URL)
        for item in data.get("data", []):
            ip = item.get("ip")
            port = item.get("port")
            protocols = item.get("protocols") or []
            proto = protocols[0].lower() if protocols else "http"
            if ip and port:
                proxies.append(f"{proto}:{ip}:{port}")
    except Exception as e:
        logging.error("Error fetching geonode proxies: %s", e)

    if proxies:
        await add_proxies(proxies)


async def scrape_proxyspace() -> None:
    """Fetch proxies from proxyspace.pro lists."""
    urls = [
        (PROXYSPACE_HTTP_URL, "http"),
        (PROXYSPACE_HTTPS_URL, "https"),
        (PROXYSPACE_SOCKS4_URL, "socks4"),
        (PROXYSPACE_SOCKS5_URL, "socks5"),
    ]
    proxies = []
    for url, proto in urls:
        try:
            text = await fetch_with_backoff(url)
            for line in text.splitlines():
                line = line.strip()
                if line:
                    proxies.append(f"{proto}:{line}")
        except Exception as e:
            logging.error("Error fetching %s: %s", url, e)
        await asyncio.sleep(1)
    if proxies:
        await add_proxies(proxies)


async def scrape_proxy_list_sites() -> None:
    for url, proto in PROXY_LIST_SITES:
        try:
            text = await fetch_with_backoff(url)
            if not text:
                continue
            soup = BeautifulSoup(text, "lxml")
            proxies = []
            textarea = soup.find("textarea")
            if textarea:
                t = textarea.get_text()
                for line in t.splitlines():
                    line = line.strip()
                    if IP_PORT_RE.match(line):
                        proxies.append(f"{proto}:{line}")
            else:
                for row in soup.select("table tbody tr"):
                    cols = row.find_all("td")
                    if len(cols) >= 2:
                        ip = cols[0].get_text(strip=True)
                        port = cols[1].get_text(strip=True)
                        if IP_PORT_RE.match(f"{ip}:{port}"):
                            proxies.append(f"{proto}:{ip}:{port}")
            if proxies:
                await add_proxies(proxies)
        except Exception as e:
            logging.error("Error fetching %s: %s", url, e)
        await asyncio.sleep(random.uniform(1, 3))


def scrape_proxy_list_download() -> None:
    interval = SCRAPERS["proxy_list_download"]
    """Fetch proxies from https://www.proxy-list.download/api."""
    types = ["http", "https", "socks4", "socks5"]
    while True:
        proxies = []
        for proto in types:
            url = f"https://www.proxy-list.download/api/v1/get?type={proto}"
            try:
                resp = requests.get(url, timeout=REQUEST_TIMEOUT)
                resp.raise_for_status()
                for line in resp.text.splitlines():
                    line = line.strip()
                    if line:
                        proxies.append(f"{proto}:{line}")
            except Exception as e:
                logging.error("Error fetching %s: %s", url, e)
            time.sleep(interval)
        if proxies:
            add_proxies_sync(proxies)
        time.sleep(interval)


def scrape_freeproxy() -> None:
    interval = SCRAPERS["freeproxy"]
    """Fetch proxies from dpangestuw Free-Proxy GitHub lists."""
    urls = [
        (FREEPROXY_HTTP_URL, "http"),
        (FREEPROXY_SOCKS4_URL, "socks4"),
        (FREEPROXY_SOCKS5_URL, "socks5"),
    ]
    while True:
        proxies = download_proxy_list(urls)
        if proxies:
            add_proxies_sync(proxies)
        time.sleep(interval)


def scrape_freshproxy() -> None:
    interval = SCRAPERS["freshproxy"]
    """Fetch proxies from the Fresh Proxy List project."""
    urls = [
        (FRESHPROXY_HTTP_URL, "http"),
        (FRESHPROXY_HTTPS_URL, "https"),
        (FRESHPROXY_SOCKS4_URL, "socks4"),
        (FRESHPROXY_SOCKS5_URL, "socks5"),
    ]
    while True:
        proxies = []
        for line in download_proxy_list(urls):
            if IP_PORT_RE.match(line.split(":", 1)[1]):
                proxies.append(line)
        if proxies:
            add_proxies_sync(proxies)
        time.sleep(interval)


def scrape_proxifly() -> None:
    interval = SCRAPERS["proxifly"]
    """Fetch proxies from the Proxifly free-proxy lists."""
    urls = [
        (PROXIFLY_HTTP_URL, "http"),
        (PROXIFLY_SOCKS4_URL, "socks4"),
        (PROXIFLY_SOCKS5_URL, "socks5"),
    ]
    while True:
        entries = download_proxy_list(urls)
        if entries:
            add_proxies_sync(entries)
        time.sleep(interval)


def scrape_freeproxy_all() -> None:
    interval = SCRAPERS["freeproxy_all"]
    """Fetch aggregated proxies from dpangestuw Free-Proxy."""
    while True:
        proxies = []
        try:
            resp = requests.get(FREEPROXY_ALL_URL, timeout=REQUEST_TIMEOUT)
            resp.raise_for_status()
            for line in resp.text.splitlines():
                line = line.strip()
                if not line:
                    continue
                if "://" in line:
                    proto, rest = line.split("://", 1)
                    proxies.append(f"{proto.lower()}:{rest}")
                elif IP_PORT_RE.match(line):
                    proxies.append(f"http:{line}")
        except Exception as e:
            logging.error("Error fetching %s: %s", FREEPROXY_ALL_URL, e)

        if proxies:
            add_proxies_sync(proxies)
        time.sleep(interval)


def scrape_kangproxy() -> None:
    interval = SCRAPERS["kangproxy"]
    """Fetch proxies from the KangProxy raw lists."""
    urls = [KANGPROXY_OLD_URL, KANGPROXY_URL]
    while True:
        proxies = []
        for url in urls:
            try:
                resp = requests.get(url, timeout=REQUEST_TIMEOUT)
                resp.raise_for_status()
                for line in resp.text.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    if "://" in line:
                        proto, rest = line.split("://", 1)
                        proxies.append(f"{proto.lower()}:{rest}")
                    elif IP_PORT_RE.match(line):
                        proxies.append(f"http:{line}")
            except Exception as e:
                logging.error("Error fetching %s: %s", url, e)
            time.sleep(1)

        if proxies:
            add_proxies_sync(proxies)
        time.sleep(interval)


def _parse_spys_list(text: str) -> list[tuple[str, str]]:
    """Return list of (ip, port) from spys.me proxy list text."""
    proxies = []
    for line in text.splitlines():
        line = line.strip()
        if (
            not line
            or line.startswith("Proxy list")
            or line.startswith("Http proxy")
            or line.startswith("Socks proxy")
            or line.startswith("Support")
            or line.startswith("BTC")
            or line.startswith("IP address")
            or line.lower().startswith("free ")
        ):
            continue
        ip_port = line.split()[0]
        if IP_PORT_RE.match(ip_port):
            ip, port = ip_port.split(":", 1)
            proxies.append((ip, port))
    return proxies


def scrape_spys() -> None:
    interval = SCRAPERS["spys"]
    """Fetch proxies from spys.me lists and store as type;ip;port."""
    urls = [
        (SPYS_HTTP_URL, "http"),
        (SPYS_SOCKS_URL, "socks5"),
    ]
    while True:
        proxies = []
        for url, proto in urls:
            try:
                resp = requests.get(url, timeout=REQUEST_TIMEOUT)
                resp.raise_for_status()
                for ip, port in _parse_spys_list(resp.text):
                    proxies.append(f"{proto}:{ip}:{port}")
            except Exception as e:
                logging.error("Error fetching %s: %s", url, e)
            time.sleep(1)

        if proxies:
            add_proxies_sync(proxies)

        time.sleep(interval)


def scrape_proxybros() -> None:
    interval = SCRAPERS["proxybros"]
    """Fetch proxies from proxybros.com free proxy list."""
    while True:
        proxies = []
        try:
            headers = {"User-Agent": random.choice(USER_AGENTS)}
            resp = requests.get(PROXYBROS_URL, headers=headers, timeout=REQUEST_TIMEOUT)
            resp.raise_for_status()
            soup = BeautifulSoup(resp.text, "lxml")
            for row in soup.select("table.proxylist-table tbody tr"):
                ip_el = row.select_one("span.proxy-ip[data-ip]")
                port_el = row.select_one("td[data-port]")
                cells = row.find_all("td")
                if ip_el and port_el and len(cells) >= 5:
                    ip = ip_el.get_text(strip=True)
                    port = port_el.get_text(strip=True)
                    proto = cells[4].get_text(strip=True).lower()
                    proxies.append(f"{proto}:{ip}:{port}")
        except Exception as e:
            logging.error("Error fetching proxybros proxies: %s", e)

        if proxies:
            add_proxies_sync(proxies)
        time.sleep(interval)


def scrape_bloody_proxies() -> None:
    """Run Bloody-Proxy-Scraper and merge results."""
    interval = SCRAPERS["bloody"]
    module_path = (
        Path(__file__).resolve().parent
        / "vendor"
        / "Bloody-Proxy-Scraper"
        / "data"
        / "proxyscraper.py"
    )
    spec = importlib.util.spec_from_file_location("bloody_proxyscraper", module_path)
    loader = spec.loader if spec else None
    if not spec or loader is None:
        logging.error("Unable to load Bloody-Proxy-Scraper module")
        return
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    Scraper = module.ProxyScraper

    while True:
        proxies: list[str] = []
        try:
            scraper = Scraper()
            result = scraper.scrape_all_proxies()
            proxies = result.get("all", [[], False])[0]
        except Exception as e:
            logging.error("Error running Bloody-Proxy-Scraper: %s", e)

        if proxies:
            add_proxies_sync(proxies)
        time.sleep(interval)


async def _irc_listener(server: str, port: int = 6667) -> None:
    """Connect to an IRC server and monitor channels for proxy announcements."""
    import string

    while True:
        reader = writer = None
        try:
            reader, writer = await asyncio.open_connection(server, port)
            nick = "bot" + "".join(
                random.choices(string.ascii_lowercase + string.digits, k=6)
            )
            writer.write(f"NICK {nick}\r\n".encode())
            writer.write(f"USER {nick} 0 * :{nick}\r\n".encode())
            await writer.drain()

            await asyncio.sleep(5)
            channels = IRC_CHANNELS[:]
            random.shuffle(channels)
            for chan in channels:
                writer.write(f"JOIN {chan}\r\n".encode())
                await writer.drain()
                await asyncio.sleep(random.uniform(1, 3))

            while True:
                line = await reader.readline()
                if not line:
                    raise ConnectionError("EOF")
                text = line.decode(errors="ignore").strip()
                if text.startswith("PING"):
                    token = text.split()[1]
                    writer.write(f"PONG {token}\r\n".encode())
                    await writer.drain()
                    continue
                proxies = extract_proxies(text)
                if proxies:
                    add_proxies_sync(proxies)
        except Exception as e:
            logging.error("IRC %s error: %s", server, e)
        finally:
            if writer:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
        await asyncio.sleep(10)


async def monitor_irc_channels() -> None:
    tasks = [asyncio.create_task(_irc_listener(s)) for s in IRC_SERVERS]
    await asyncio.gather(*tasks)


def bencode(value) -> bytes:
    if isinstance(value, int):
        return b"i" + str(value).encode() + b"e"
    if isinstance(value, bytes):
        return str(len(value)).encode() + b":" + value
    if isinstance(value, str):
        b = value.encode()
        return str(len(b)).encode() + b":" + b
    if isinstance(value, list):
        return b"l" + b"".join(bencode(v) for v in value) + b"e"
    if isinstance(value, dict):
        items = sorted(value.items())
        return b"d" + b"".join(bencode(k) + bencode(v) for k, v in items) + b"e"
    raise TypeError("Unsupported type for bencoding")


def bdecode(data: bytes):
    def parse(index: int):
        lead = data[index : index + 1]
        if lead == b"i":
            end = data.index(b"e", index + 1)
            return int(data[index + 1 : end]), end + 1
        if lead == b"l":
            index += 1
            lst = []
            while data[index : index + 1] != b"e":
                item, index = parse(index)
                lst.append(item)
            return lst, index + 1
        if lead == b"d":
            index += 1
            d = {}
            while data[index : index + 1] != b"e":
                key, index = parse(index)
                val, index = parse(index)
                d[key] = val
            return d, index + 1
        if lead.isdigit():
            colon = data.index(b":", index)
            length = int(data[index:colon])
            start = colon + 1
            end = start + length
            return data[start:end], end
        raise ValueError("Invalid bencode")

    value, _ = parse(0)
    return value


class DHTClient(asyncio.DatagramProtocol):
    def __init__(self, node_id: bytes):
        self.node_id = node_id
        self.transactions: dict[bytes, asyncio.Future] = {}
        self.transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport  # type: ignore

    def datagram_received(self, data: bytes, addr) -> None:
        try:
            msg = bdecode(data)
        except Exception:
            return
        tid = msg.get(b"t")
        fut = self.transactions.pop(tid, None)
        if fut and not fut.done():
            fut.set_result((msg, addr))

    async def _query(
        self, addr: tuple[str, int], msg: dict
    ) -> tuple[dict, tuple[str, int]]:
        tid = os.urandom(2)
        msg[b"t"] = tid
        data = bencode(msg)
        fut = asyncio.get_running_loop().create_future()
        self.transactions[tid] = fut
        assert self.transport is not None
        self.transport.sendto(data, addr)
        try:
            return await asyncio.wait_for(fut, timeout=5)
        finally:
            self.transactions.pop(tid, None)

    async def find_node(self, addr: tuple[str, int], target: bytes):
        msg = {
            b"y": b"q",
            b"q": b"find_node",
            b"a": {b"id": self.node_id, b"target": target},
        }
        return await self._query(addr, msg)

    async def get_peers(self, addr: tuple[str, int], info_hash: bytes):
        msg = {
            b"y": b"q",
            b"q": b"get_peers",
            b"a": {b"id": self.node_id, b"info_hash": info_hash},
        }
        return await self._query(addr, msg)


def _decode_nodes(data: bytes) -> list[tuple[str, int]]:
    nodes = []
    for i in range(0, len(data), 26):
        segment = data[i : i + 26]
        if len(segment) < 26:
            continue
        ip = socket.inet_ntoa(segment[20:24])
        port = struct.unpack("!H", segment[24:26])[0]
        nodes.append((ip, port))
    return nodes


def _decode_peers(values: list) -> list[tuple[str, int]]:
    peers = []
    for val in values:
        if len(val) != 6:
            continue
        ip = socket.inet_ntoa(val[:4])
        port = struct.unpack("!H", val[4:6])[0]
        peers.append((ip, port))
    return peers


async def crawl_dht() -> None:
    loop = asyncio.get_running_loop()
    node_id = os.urandom(20)
    transport, client = await loop.create_datagram_endpoint(
        lambda: DHTClient(node_id), local_addr=("0.0.0.0", 0)
    )

    queue: asyncio.Queue[tuple[str, int]] = asyncio.Queue()
    visited: set[tuple[str, int]] = set()

    for host, port in BOOTSTRAP_NODES:
        try:
            infos = await loop.getaddrinfo(
                host, port, family=socket.AF_INET, type=socket.SOCK_DGRAM
            )
            if infos:
                ip = infos[0][4][0]
                queue.put_nowait((ip, port))
        except Exception as e:
            logging.warning("Failed to resolve %s: %s", host, e)

    sem = asyncio.Semaphore(MAX_DHT_CONCURRENCY)
    count = 0

    async def worker() -> None:
        nonlocal count
        batch: list[str] = []
        while True:
            ip, port = await queue.get()
            if (ip, port) in visited:
                queue.task_done()
                continue
            visited.add((ip, port))
            async with sem:
                try:
                    resp, _ = await client.find_node((ip, port), os.urandom(20))
                    nodes = _decode_nodes(resp.get(b"r", {}).get(b"nodes", b""))
                    for n in nodes:
                        if n not in visited:
                            queue.put_nowait(n)
                except Exception:
                    pass
                try:
                    resp, _ = await client.get_peers((ip, port), os.urandom(20))
                    vals = resp.get(b"r", {}).get(b"values", [])
                    peers = _decode_peers(vals)
                    for p_ip, p_port in peers:
                        if p_port in PROXY_PORTS:
                            batch.append(f"{p_ip}:{p_port}")
                    if len(batch) >= 50:
                        add_proxies_sync(batch)
                        batch = []
                except Exception:
                    pass

                count += 1
                if count % DHT_LOG_EVERY == 0:
                    logging.info(
                        "DHT: visited %s nodes, proxies %s",
                        len(visited),
                        len(proxy_set),
                    )
                    if batch:
                        add_proxies_sync(batch)
                        batch = []
            queue.task_done()

    workers = [asyncio.create_task(worker()) for _ in range(MAX_DHT_WORKERS)]
    await asyncio.gather(*workers)


async def run_proxxy() -> None:
    """Background task running the proXXy asynchronous scraper."""
    interval = SCRAPERS["proxxy"]
    while True:
        async for batch in fetch_proxxy_sources():
            if not batch:
                continue
            add_proxies_sync(batch)
        await asyncio.sleep(interval)


async def parse_list(session: aiohttp.ClientSession, url: str) -> list:
    async with session.get(url, timeout=REQUEST_TIMEOUT) as resp:
        text = await resp.text()
    return [line.strip() for line in text.splitlines() if line.strip()]


async def scrape_openproxylist(interval: float, concurrency: int):
    sem = asyncio.Semaphore(concurrency)
    session = await get_aiohttp_session()
    while True:
        tasks = []
        for url in OPENPROXYLIST_ENDPOINTS:
            async with sem:
                tasks.append(parse_list(session, url))
        results = await asyncio.gather(*tasks, return_exceptions=True)
        entries: list[str] = []
        for proxies in results:
            if isinstance(proxies, list):
                entries.extend(proxies)
        add_proxies_sync(entries)
        await asyncio.sleep(interval)


async def scrape_proxyhub(interval: float, concurrency: int) -> None:
    """Run ProxyHub's asynchronous fetcher alongside other scrapers."""

    async def _fetch(url: str, sem: asyncio.Semaphore) -> List[str]:
        async with sem:
            try:
                return await fetch_source(url)
            except Exception as e:
                logging.error("proxyhub source error %s: %s", url, e)
                return []

    while True:
        sem = asyncio.Semaphore(concurrency)
        tasks = [asyncio.create_task(_fetch(url, sem)) for url in SOURCE_LIST]
        for task in asyncio.as_completed(tasks):
            proxies = await task
            if not proxies:
                continue
            add_proxies_sync(proxies)
        await asyncio.sleep(interval)


TR_RE = re.compile(
    r"<td>(.*?)</td>\s*"
    r"<td><script>document.write\('(.*?)'\)\s*</script></td>\s*"
    r"<td><script>document.write\(gp.dep\('(.*?)'\)\)\s*</script></td>\s*"
    r"<td .*?>(.*?)</td>\s*"
    r"<td>(.*?)</td>\s*"
    r"<td></td>\s*"
    r"<td .*?>(.*?)</td>\s*"
    r"<td .*?>(.*?)</td>",
    re.S,
)

PAGE_DIV_RE = re.compile(r'<div class="pagenavi">(.*?)</div>', re.S)
PAGE_LINK_RE = re.compile(r"<a .*?>(.*?)</a>")


def _gp_page_count(text: str) -> int:
    text = text.replace("\n", " ")
    count = 0
    for div in PAGE_DIV_RE.findall(text):
        for link in PAGE_LINK_RE.findall(div):
            try:
                count = int(link)
            except Exception:
                pass
    return count


def _parse_gatherproxy(text: str) -> list[tuple[str, str, str, str, int]]:
    text = text.replace("\n", " ")
    proxies = []
    for g in TR_RE.findall(text):
        try:
            port = str(int(g[2], 16))
            resp_time = int(g[6].replace("ms", ""))
        except Exception:
            continue
        proxies.append((g[1], port, g[3], g[4], resp_time))
    return proxies


async def scrape_gatherproxy(interval: float, concurrency: int):
    sem = asyncio.Semaphore(concurrency)
    while True:
        proxies: list[tuple[str, str, str, str, int]] = []
        session = await get_aiohttp_session()

        async def fetch_page(page: int) -> str:
            async with sem:
                resp = await session.post(
                    GATHER_PROXY_URI,
                    data={
                        "Type": "Elite",
                        "PageIdx": page,
                        "Uptime": GATHER_PROXY_MIN_UPTIME,
                    },
                    timeout=REQUEST_TIMEOUT,
                )
                return await resp.text()

        try:
            first = await fetch_page(1)
        except Exception as e:
            logging.error("gatherproxy page 1 error: %s", e)
            await asyncio.sleep(interval)
            continue

        proxies.extend(_parse_gatherproxy(first))
        pages = _gp_page_count(first)

        tasks = [asyncio.create_task(fetch_page(p)) for p in range(2, pages + 1)]
        for task in asyncio.as_completed(tasks):
            try:
                html = await task
            except Exception as e:
                logging.error("gatherproxy fetch error: %s", e)
                continue
            proxies.extend(_parse_gatherproxy(html))

        if proxies:
            entries = [
                f"{typ.lower()}:{ip}:{port}" for ip, port, typ, country, rt in proxies
            ]
            add_proxies_sync(entries)
        await asyncio.sleep(interval)


async def run_periodic(func, interval: float) -> None:
    while True:
        await func()
        await asyncio.sleep(interval)


async def main() -> None:
    tasks = [
        asyncio.create_task(run_periodic(scrape_mt_proxies, SCRAPERS["mtpro"])),
        asyncio.create_task(run_periodic(monitor_paste_feeds, SCRAPERS["paste"])),
        asyncio.create_task(crawl_dht()),
        asyncio.create_task(run_periodic(scrape_tor_relays, SCRAPERS["tor"])),
        asyncio.create_task(monitor_irc_channels()),
        asyncio.create_task(run_periodic(scrape_proxyscrape, SCRAPERS["proxyscrape"])),
        asyncio.create_task(run_periodic(scrape_gimmeproxy, SCRAPERS["gimmeproxy"])),
        asyncio.create_task(run_periodic(scrape_pubproxy, SCRAPERS["pubproxy"])),
        asyncio.create_task(
            run_periodic(scrape_proxykingdom, SCRAPERS["proxykingdom"])
        ),
        asyncio.create_task(run_periodic(scrape_geonode, SCRAPERS["geonode"])),
        asyncio.create_task(run_periodic(scrape_proxyspace, SCRAPERS["proxyspace"])),
        asyncio.create_task(
            run_periodic(scrape_proxy_list_sites, SCRAPERS["proxy_list_sites"])
        ),
        asyncio.create_task(writer_loop()),
        asyncio.create_task(run_proxxy()),
        asyncio.create_task(scrape_proxyhub(PROXYHUB_INTERVAL, PROXYHUB_CONCURRENCY)),
        asyncio.create_task(
            scrape_gatherproxy(GATHER_PROXY_INTERVAL, GATHER_PROXY_CONCURRENCY)
        ),
        asyncio.create_task(
            scrape_openproxylist(OPENPROXYLIST_INTERVAL, OPENPROXYLIST_CONCURRENCY)
        ),
        asyncio.create_task(asyncio.to_thread(scrape_proxyscraper_sources)),
        asyncio.create_task(asyncio.to_thread(scrape_proxy_list_download)),
        asyncio.create_task(asyncio.to_thread(scrape_freeproxy)),
        asyncio.create_task(asyncio.to_thread(scrape_freshproxy)),
        asyncio.create_task(asyncio.to_thread(scrape_proxifly)),
        asyncio.create_task(asyncio.to_thread(scrape_freeproxy_all)),
        asyncio.create_task(asyncio.to_thread(scrape_kangproxy)),
        asyncio.create_task(asyncio.to_thread(scrape_spys)),
        asyncio.create_task(asyncio.to_thread(scrape_proxybros)),
        asyncio.create_task(asyncio.to_thread(scrape_bloody_proxies)),
    ]
    await asyncio.gather(*tasks)


if __name__ == "__main__":
    import sys

    if len(sys.argv) == 3:
        success = filter_p1(sys.argv[1], sys.argv[2])
        sys.exit(0 if success else 1)

    try:
        import uvloop

        asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
    except Exception:
        pass
    asyncio.run(main())
