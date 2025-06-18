import asyncio
import aiohttp
import argparse
import time
from pathlib import Path
from typing import Set

from scrape_proxies import (
    filter_p1,
    filter_p2,
    load_blacklists,
    PROXYSCRAPE_SOCKS4_URL,
    PROXYSCRAPE_SOCKS5_URL,
    PROXYSPACE_SOCKS4_URL,
    PROXYSPACE_SOCKS5_URL,
    FREEPROXY_SOCKS4_URL,
    FREEPROXY_SOCKS5_URL,
    FRESHPROXY_SOCKS4_URL,
    FRESHPROXY_SOCKS5_URL,
    PROXIFLY_SOCKS4_URL,
    PROXIFLY_SOCKS5_URL,
)

DURATION = 300  # 5 minutes
SOURCES = [
    PROXYSCRAPE_SOCKS4_URL,
    PROXYSCRAPE_SOCKS5_URL,
    PROXYSPACE_SOCKS4_URL,
    PROXYSPACE_SOCKS5_URL,
    FREEPROXY_SOCKS4_URL,
    FREEPROXY_SOCKS5_URL,
    FRESHPROXY_SOCKS4_URL,
    FRESHPROXY_SOCKS5_URL,
    PROXIFLY_SOCKS4_URL,
    PROXIFLY_SOCKS5_URL,
]


def parse_proxies(text: str, proto: str) -> list[str]:
    proxies = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        if '://' in line:
            pproto, rest = line.split('://', 1)
            ip_port = rest
        else:
            pproto = proto
            ip_port = line
        if ':' not in ip_port:
            continue
        ip, port = ip_port.split(':', 1)
        if not port.isdigit():
            continue
        proxies.append(f'{pproto}:{ip}:{port}')
    return proxies


async def fetch_source(session: aiohttp.ClientSession, url: str) -> list[str]:
    proto = 'socks4' if 'socks4' in url else 'socks5'
    try:
        async with session.get(url, timeout=10) as resp:
            text = await resp.text()
    except Exception:
        return []
    return parse_proxies(text, proto)


async def gather(queue: asyncio.Queue[str]) -> None:
    end = time.time() + DURATION
    async with aiohttp.ClientSession() as session:
        while time.time() < end:
            tasks = [asyncio.create_task(fetch_source(session, u)) for u in SOURCES]
            for t in asyncio.as_completed(tasks):
                for p in await t:
                    await queue.put(p)
            await asyncio.sleep(2)


def write_result(proxies: Set[str]) -> None:
    desktop = Path.home() / 'Desktop'
    desktop.mkdir(parents=True, exist_ok=True)
    out = desktop / 'last.txt'
    out.write_text('\n'.join(sorted(proxies)))
    print(f'Wrote {len(proxies)} proxies to {out}')


async def worker(queue: asyncio.Queue[str], good: Set[str]) -> None:
    seen: Set[str] = set()
    end = time.time() + DURATION
    while time.time() < end or not queue.empty():
        try:
            proxy = await asyncio.wait_for(queue.get(), timeout=1)
        except asyncio.TimeoutError:
            continue
        if proxy in seen:
            queue.task_done()
            continue
        seen.add(proxy)
        if await asyncio.to_thread(filter_p1, proxy, 'pop3'):
            accepted, _ = await filter_p2([proxy])
            if accepted:
                good.add(proxy)
        queue.task_done()


async def main(_: argparse.Namespace) -> None:
    await load_blacklists()
    queue: asyncio.Queue[str] = asyncio.Queue()
    good: Set[str] = set()
    producer = asyncio.create_task(gather(queue))
    workers = [asyncio.create_task(worker(queue, good)) for _ in range(50)]
    await producer
    await queue.join()
    for w in workers:
        w.cancel()
    write_result(good)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Quick SOCKS4/5 scraper')
    parser.add_argument('--optionals', action='store_true', help='enable optional mode')
    args = parser.parse_args()
    asyncio.run(main(args))
