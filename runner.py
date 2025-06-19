import argparse
import asyncio
import logging
import sys
from typing import List

import scrape_proxies as sp


async def cmd_scrape(args: argparse.Namespace) -> None:
    await sp.main(
        [
            f"--timeout={args.timeout}",
            f"--concurrency={args.concurrency}",
            f"--stats-interval={args.stats_interval}",
            f"--output-dir={args.output_dir}",
        ]
    )


async def cmd_collect(args: argparse.Namespace) -> None:
    await sp.save_proxies_json(args.output)


async def cmd_fetch(args: argparse.Namespace) -> None:
    proxies = await sp.fetch_proxies(types=args.types, limit=args.limit)
    for p in proxies:
        print(p)


async def cmd_classify(args: argparse.Namespace) -> None:
    proxies = [line.strip() for line in sys.stdin if line.strip()]
    result = await sp.classify(proxies, timeout=args.timeout)
    for p in result:
        print(p)


async def cmd_probe(args: argparse.Namespace) -> None:
    proxies = [line.strip() for line in sys.stdin if line.strip()]
    counts = await sp.probe_proxies(proxies, args.concurrency, args.timeout)
    for proto, count in counts.items():
        print(f"{proto}: {count}")


async def main(argv: List[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="roxy runner")
    sub = parser.add_subparsers(dest="command", required=True)

    sc = sub.add_parser("scrape", help="full scraping pipeline")
    sc.add_argument("--timeout", type=float, default=5.0)
    sc.add_argument("--concurrency", type=int, default=5000)
    sc.add_argument("--stats-interval", type=float, default=1.0)
    sc.add_argument("--output-dir", type=str, default=".")
    sc.set_defaults(func=cmd_scrape)

    co = sub.add_parser("collect", help="collect proxies and save to JSON")
    co.add_argument("output", help="output JSON path")
    co.set_defaults(func=cmd_collect)

    fe = sub.add_parser("fetch", help="fetch sample proxy list")
    fe.add_argument("--types", nargs="*", default=None)
    fe.add_argument("--limit", type=int, default=100)
    fe.set_defaults(func=cmd_fetch)

    cl = sub.add_parser("classify", help="classify proxies from stdin")
    cl.add_argument("--timeout", type=float, default=2.0)
    cl.set_defaults(func=cmd_classify)

    pr = sub.add_parser("probe", help="probe proxies from stdin")
    pr.add_argument("--concurrency", type=int, default=10000)
    pr.add_argument("--timeout", type=float, default=2.0)
    pr.set_defaults(func=cmd_probe)

    parser.add_argument("--log-level", default="INFO")

    args = parser.parse_args(argv)
    logging.basicConfig(level=getattr(logging, args.log_level.upper(), logging.INFO))
    await args.func(args)


if __name__ == "__main__":
    asyncio.run(main())
