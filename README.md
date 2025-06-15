# Proxy Scraper

This repository contains a Python script that continuously gathers proxies from multiple sources. It scrapes MTProto and SOCKS5 proxies from [mtpro.xyz](https://mtpro.xyz) and also monitors several pastebin-like feeds for `IP:PORT` entries. New proxies are written to `proxies.txt` and may be prefixed with `http:` or `socks5:` when the protocol is detected.

## Requirements
- Python 3
- `requests` library (`pip install requests`)

## Usage
Run the scraper:

```bash
python3 scrape_proxies.py
```

The script continuously fetches the latest proxies from `https://mtpro.xyz/api/?type=mtproto` and `https://mtpro.xyz/api/?type=socks` while also checking the configured paste feeds. Newly discovered proxies are deduplicated and written to `proxies.txt`.
