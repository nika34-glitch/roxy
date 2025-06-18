# Roxy Proxy Scraper

This project collects proxy addresses from various public sources. Some scrapers
rely on third party projects located under `vendor/` which are configured as Git
submodules. Install dependencies and update submodules before running the
`scrape_proxies.py` script:

```bash
pip install -r requirements.txt  # install requests, aiofiles, etc.

git submodule update --init --recursive
```

The script writes statistics to `stats.json` every second when running. Ensure
`BeautifulSoup` and either `lxml` or Python's builtin HTML parser are
available.

## Quick SOCKS scraper

`optional_socks_scraper.py` collects only SOCKS4 and SOCKS5 proxies for five
minutes and stores the working ones in `~/Desktop/last.txt`. Run it as:

```bash
python optional_socks_scraper.py --optionals
```

