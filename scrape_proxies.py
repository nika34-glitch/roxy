import requests
import time
import sys
import threading
import random
import re

MTPROTO_URL = "https://mtpro.xyz/api/?type=mtproto"
SOCKS_URL = "https://mtpro.xyz/api/?type=socks"
OUTPUT_FILE = "proxies.txt"

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

proxy_set = set()
lock = threading.Lock()


def write_proxies_to_file():
    with lock:
        with open(OUTPUT_FILE, "w") as f:
            f.write("\n".join(sorted(proxy_set)))


def fetch_json(url):
    response = requests.get(url, timeout=10)
    response.raise_for_status()
    return response.json()


def scrape_mt_proxies(interval: int = MT_INTERVAL) -> None:
    while True:
        proxies = []
        try:
            mt_list = fetch_json(MTPROTO_URL)
            for item in mt_list:
                host = item.get("host")
                port = item.get("port")
                if host and port:
                    proxies.append(f"{host}:{port}")
        except Exception as e:
            print(f"Error fetching mtproto proxies: {e}", file=sys.stderr)
        try:
            socks_list = fetch_json(SOCKS_URL)
            for item in socks_list:
                ip = item.get("ip")
                port = item.get("port")
                if ip and port:
                    proxies.append(f"{ip}:{port}")
        except Exception as e:
            print(f"Error fetching socks proxies: {e}", file=sys.stderr)

        if proxies:
            with lock:
                added = False
                for p in proxies:
                    if p not in proxy_set:
                        proxy_set.add(p)
                        added = True
                if added:
                    write_proxies_to_file()
        time.sleep(interval)


def fetch_with_backoff(url: str, max_retries: int = 5) -> str:
    delay = 1
    for _ in range(max_retries):
        try:
            headers = {"User-Agent": random.choice(USER_AGENTS)}
            resp = requests.get(url, headers=headers, timeout=10)
            if resp.status_code >= 400:
                raise requests.HTTPError(resp.status_code)
            return resp.text
        except Exception:
            sleep_time = delay + random.uniform(0, 1)
            time.sleep(sleep_time)
            delay = min(delay * 2, 60)
    return ""


def extract_proxies(text: str) -> list[str]:
    found = []
    for m in re.finditer(r"((?:\d{1,3}\.){3}\d{1,3}):(\d{1,5})", text):
        ip = m.group(1)
        port = int(m.group(2))
        if not (1 <= port <= 65535):
            continue
        octets = ip.split(".")
        if any(not 0 <= int(o) <= 255 for o in octets):
            continue
        snippet = text[max(0, m.start() - 20): m.end() + 20].lower()
        protocol = "socks5" if "socks5" in snippet else "http"
        found.append(f"{protocol}:{ip}:{port}")
    return found


def monitor_paste_feeds(interval: int = PASTE_INTERVAL) -> None:
    while True:
        for feed in PASTE_FEEDS:
            text = fetch_with_backoff(feed)
            if text:
                proxies = extract_proxies(text)
                with lock:
                    added = False
                    for p in proxies:
                        if p not in proxy_set:
                            proxy_set.add(p)
                            added = True
                    if added:
                        write_proxies_to_file()
            time.sleep(random.uniform(*FEED_DELAY_RANGE))
        time.sleep(interval)


def main() -> None:
    threads = [
        threading.Thread(target=scrape_mt_proxies, daemon=True),
        threading.Thread(target=monitor_paste_feeds, daemon=True),
    ]
    for t in threads:
        t.start()
    while True:
        time.sleep(1)


if __name__ == "__main__":
    main()
