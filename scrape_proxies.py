# ProxyHub scraping utilities

import asyncio
import importlib.util
import logging
import re
import random
import sys
import types
from pathlib import Path
from typing import List

__all__ = ["fetch_proxies"]

_log = logging.getLogger(__name__)

_PROVIDER_MODULE = None


def _load_provider_module():
    """Dynamically load proxyhub's providers module with minimal stubs."""
    global _PROVIDER_MODULE
    if _PROVIDER_MODULE is not None:
        return _PROVIDER_MODULE

    base_path = Path(__file__).resolve().parent / "proxyhub" / "proxyhub" / "providers.py"

    # minimal proxyhub package stubs for relative imports
    pkg = types.ModuleType("proxyhub")
    pkg.__path__ = [str(base_path.parent)]
    sys.modules.setdefault("proxyhub", pkg)

    errors = types.ModuleType("proxyhub.errors")

    class BadStatusError(Exception):
        pass

    errors.BadStatusError = BadStatusError
    sys.modules.setdefault("proxyhub.errors", errors)

    utils = types.ModuleType("proxyhub.utils")
    utils.log = _log
    utils.IPPattern = re.compile(
        r"(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)"
    )
    utils.IPPortPatternGlobal = re.compile(
        r"(?P<ip>(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?))"
        r"(?=.*?(?:(?:(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?))|(?P<port>\d{2,5})))",
        flags=re.DOTALL,
    )

    def get_headers(rv: bool = False):
        _rv = str(random.randint(1000, 9999)) if rv else ""
        headers = {
            "User-Agent": f"PxBroker/0.0/{_rv}",
            "Accept": "*/*",
            "Accept-Encoding": "gzip, deflate",
            "Pragma": "no-cache",
            "Cache-control": "no-cache",
            "Cookie": "cookie=ok",
            "Referer": "https://www.google.com/",
        }
        return headers if not rv else (headers, _rv)

    utils.get_headers = get_headers
    sys.modules.setdefault("proxyhub.utils", utils)

    spec = importlib.util.spec_from_file_location("proxyhub.providers", base_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules["proxyhub.providers"] = module
    spec.loader.exec_module(module)  # type: ignore
    _PROVIDER_MODULE = module
    return module


async def fetch_proxies(types: List[str] = None, limit: int = 100) -> List[str]:
    """Asynchronously collect up to ``limit`` proxies from all sources."""

    if types is None:
        types = ["HTTP", "HTTPS"]

    provider_mod = _load_provider_module()
    providers = provider_mod.PROVIDERS

    tasks = [p.get_proxies() for p in providers]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    collected = []
    seen = set()

    for provider, result in zip(providers, results):
        if isinstance(result, Exception):  # pragma: no cover - network errors
            _log.warning(
                "provider %s failed: %s",
                getattr(provider, "domain", provider.url),
                result,
            )
            continue
        for host, port, proto in result:
            if proto and not set(proto) & set(types):
                continue
            proxy = f"{host}:{port}"
            if proxy not in seen:
                seen.add(proxy)
                collected.append(proxy)
                if len(collected) >= limit:
                    return collected
    return collected
