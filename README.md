# Proxy Scraper

This repository contains a Python script that continuously gathers proxies from multiple sources. It scrapes MTProto and SOCKS5 proxies from [mtpro.xyz](https://mtpro.xyz), monitors several pastebin-like feeds for `IP:PORT` entries, listens to numerous IRC channels where proxies are shared, polls a few open proxy APIs, and periodically collects public Tor relay addresses from the [Onionoo](https://onionoo.torproject.org) service. New proxies are written to `proxies.txt` and may be prefixed with `http:` or `socks5:` when the protocol is detected.

## Requirements
- Python 3
- `requests` library (`pip install requests`)

## Usage
Run the scraper:

```bash
python3 scrape_proxies.py
```

The script continuously fetches the latest proxies from `https://mtpro.xyz/api/?type=mtproto` and `https://mtpro.xyz/api/?type=socks`, listens on many proxy-sharing IRC channels, queries a collection of free proxy APIs, and checks the configured paste feeds. Newly discovered proxies are deduplicated and written to `proxies.txt`.
The APIs polled include ProxyScrape, ProxyKingdom, GimmeProxy and PubProxy. Each endpoint is queried approximately every 0.3 seconds.
