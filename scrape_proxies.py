import requests
import time
import sys

MTPROTO_URL = "https://mtpro.xyz/api/?type=mtproto"
SOCKS_URL = "https://mtpro.xyz/api/?type=socks"
OUTPUT_FILE = "proxies.txt"
INTERVAL = 1  # seconds

def fetch_json(url):
    response = requests.get(url, timeout=10)
    response.raise_for_status()
    return response.json()

def main():
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
            with open(OUTPUT_FILE, "w") as f:
                f.write("\n".join(proxies))
        time.sleep(INTERVAL)

if __name__ == "__main__":
    main()
