# Proxy Scraper

This repository contains a simple Python script for scraping MTProto and SOCKS5 proxies from [mtpro.xyz](https://mtpro.xyz) every second. The collected proxies are saved to `proxies.txt` in `ip:port` format.

## Requirements
- Python 3
- `requests` library (`pip install requests`)

## Usage
Run the scraper:

```bash
python3 scrape_proxies.py
```

The script continuously fetches the latest proxies from `https://mtpro.xyz/api/?type=mtproto` and `https://mtpro.xyz/api/?type=socks`. Each successful fetch overwrites `proxies.txt` with the current list of proxies.
