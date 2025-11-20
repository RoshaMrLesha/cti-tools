#!/usr/bin/env python3
"""
bulk_domain_suspension_check.py

A tool to scan all cases from an API, extract domains, run WHOIS queries,
and detect suspended statuses (clientHold / serverHold).

Requirements:
    pip install requests tldextract rich

Usage:
python bulk_domain_suspension_check.py \
  -e myemail -p mypass \
  --api-base "https://api.example.com/cases?status=open&brand=Acme" \
  --threads 10
"""

import argparse
import re
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse, parse_qsl, unquote

import requests
import tldextract
from rich.console import Console
from rich.progress import (
    Progress,
    SpinnerColumn,
    BarColumn,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)
from rich.table import Table
from rich.text import Text

console = Console()

# ----------------- User-editable defaults -----------------
API_BASE_DEFAULT = "https://api.example.com"  # placeholder
LOGIN_ENDPOINT = "/api/v1//auth/sign_in"
CASES_ENDPOINT = "/api/v1/illigal_cases"

PER_PAGE_DEFAULT = 100
THREADS_DEFAULT = 5
WHOIS_TIMEOUT_DEFAULT = 30  # seconds
ESTIMATED_SECS_PER_WHOIS = 1.7  # for estimation; adjustable
WARN_THRESHOLD_SECONDS = 15 * 60  # 15 min
# -----------------------------------------------------------


def parse_args():
    p = argparse.ArgumentParser(
        description="Bulk WHOIS tool to find domains in clientHold/serverHold."
    )
    p.add_argument("-e", "--email", required=True, help="API email")
    p.add_argument("-p", "--password", required=True, help="API password")
    p.add_argument(
        "--api-base",
        default=API_BASE_DEFAULT,
        help=(
            "Base URL for cases. Can include path and query params for filtering, "
            "e.g. 'https://api.example.com/cases?status=open&brand=x'. "
            "Per-page/page parameters will be added if missing."
        ),
    )
    p.add_argument(
        "--threads",
        type=int,
        default=THREADS_DEFAULT,
        help=f"Number of concurrent WHOIS lookups (default {THREADS_DEFAULT})",
    )
    p.add_argument(
        "--per-page",
        type=int,
        default=PER_PAGE_DEFAULT,
        help="Cases per page default if not set in query params (default 100)",
    )
    p.add_argument(
        "--whois-timeout",
        type=int,
        default=WHOIS_TIMEOUT_DEFAULT,
        help="Timeout per WHOIS lookup (default 10s)",
    )
    p.add_argument(
        "--ui-base",
        default="https://web.example.com/cases?status=suspended",
        help="Placeholder link to view suspended cases",
    )
    p.add_argument("--verbose", action="store_true")
    return p.parse_args()


# ----------------- API Helpers -----------------


def login(api_base: str, email: str, password: str, verbose: bool) -> str:
    """
    Sign-in using email/password.

    - POST to LOGIN_ENDPOINT on the same host as api_base.
    - Expect cookies `_obp_session` and `_obp_token` to be set.
    - Return an authenticated requests.Session carrying those cookies.
    """
    console.print("[bold]Stage 0: Logging in[/bold]")

    session = requests.Session()

    parsed = urlparse(api_base)
    if parsed.scheme:
        base_root = f"{parsed.scheme}://{parsed.netloc}"
    else:
        base_root = api_base.rstrip("/")

    url = base_root.rstrip("/") + LOGIN_ENDPOINT

    try:
        resp = session.post(
            url, json={"email": email, "password": password}, timeout=15
        )
    except Exception as e:
        raise RuntimeError(f"Login request failed: {e}")

    if verbose:
        console.print(f"Login URL: {url}")
        console.print(f"Login response: HTTP {resp.status_code}")
        console.print(f"Set-Cookie: {resp.headers.get('Set-Cookie', '')}")

    if resp.status_code != 200:
        raise RuntimeError(f"Login failed: HTTP {resp.status_code} - {resp.text}")

    # Raw cookies from the session's jar
    cookies_raw = session.cookies.get_dict()
    # URL-decoded view of the cookies (for checking / logging)
    cookies_decoded = {k: unquote(v) for k, v in cookies_raw.items()}

    if verbose:
        console.print(f"Cookies (raw): {cookies_raw}")
        console.print(f"Cookies (decoded): {cookies_decoded}")

    if "_obp_token" not in cookies_decoded:
        raise RuntimeError(
            "Login succeeded but expected cookie '_obp_token' "
            "was not found (after URL-decoding). Adjust login endpoint or cookie names if needed."
        )

    console.print("[green]Login successful. Auth cookies stored in session.[/green]")
    # Note: session itself still holds the original cookie values for HTTP use.
    return session




def prepare_cases_url_and_params(
    api_base: str, per_page_default: int, verbose: bool
) -> Tuple[str, List[Tuple[str, str]], int]:
    """
    Parse --api-base which can include path and query params for filtering/search.

    - If api_base has no scheme, treat it as a bare base and append /cases.
    - If it has scheme, we keep its path as-is (even if /cases/search etc.).
    - Query parameters may repeat (e.g. by_states[]=open&by_states[]=change_detected),
      so we preserve ALL values using a list of (key, value) tuples.
    - We add defaults for per_page and size if they are not already present.
    - Returns:
        base_url (without query),
        base_params (list of (key, value)),
        effective_page_size (int) used for pagination heuristics.
    """
    parsed = urlparse(api_base)

    if not parsed.scheme:
        # No scheme -> treat as simple host/base, use /cases
        base_url = api_base.rstrip("/") + CASES_ENDPOINT
        base_params: List[Tuple[str, str]] = []
    else:
        # Use provided path as-is; if empty, default to /cases
        path = parsed.path or CASES_ENDPOINT
        base_url = f"{parsed.scheme}://{parsed.netloc}{path}"
        # keep_blank_values=True to preserve things like key=&
        base_params = list(parse_qsl(parsed.query, keep_blank_values=True))

    # Check if per_page / size already present (possibly multiple times)
    has_per_page = any(k == "per_page" for k, _ in base_params)
    has_size = any(k == "size" for k, _ in base_params)

    # Only add defaults if not present at all
    if not has_per_page:
        base_params.append(("per_page", str(per_page_default)))
    if not has_size:
        base_params.append(("size", str(per_page_default)))

    # Determine effective page size.
    # Prefer the last per_page, otherwise last size, otherwise default.
    effective_page_size = per_page_default
    found = False
    for k, v in reversed(base_params):
        if k == "per_page":
            try:
                effective_page_size = int(v)
                found = True
            except ValueError:
                pass
            break
    if not found:
        for k, v in reversed(base_params):
            if k == "size":
                try:
                    effective_page_size = int(v)
                except ValueError:
                    pass
                break

    if verbose:
        console.print(f"Cases base URL: {base_url}")
        console.print(f"Base query params (preserving duplicates): {base_params}")
        console.print(f"Effective page size: {effective_page_size}")

    return base_url, base_params, effective_page_size


def fetch_cases_page(
    session: requests.Session,
    base_url: str,
    base_params: List[Tuple[str, str]],
    page: int,
    verbose: bool,
) -> Dict:
    """
    Fetch a single page of cases using the authenticated session and provided filters.
    """
    params = list(base_params)
    params.append(("page", str(page)))

    resp = session.get(base_url, params=params, timeout=30)
    if verbose:
        console.print(f"GET {resp.url} -> {resp.status_code}")
    resp.raise_for_status()
    return resp.json()


def collect_all_cases(
    session: requests.Session,
    base_url: str,
    base_params: List[Tuple[str, str]],
    effective_page_size: int,
    verbose: bool,
) -> List[Dict]:
    console.print("[bold]Stage 1: Collecting cases[/bold]")

    cases: List[Dict] = []
    page = 1
    retry_once = False

    while True:
        try:
            js = fetch_cases_page(session, base_url, base_params, page, verbose)
        except Exception as e:
            if not retry_once:
                console.print(
                    f"[yellow]Error fetching page {page}: {e}. Retrying once...[/yellow]"
                )
                retry_once = True
                try:
                    js = fetch_cases_page(session, base_url, base_params, page, verbose)
                except Exception as e2:
                    raise RuntimeError(f"Failed again fetching page {page}: {e2}")
            else:
                raise

        data = js.get("data", [])
        total_cases = js.get("total_count", "Unknown")
        cases.extend(data)
        console.print(f"  Page {page}: {len(data)} cases (total {len(cases)}) out of {total_cases}")

        # Stop when last page is reached (fewer than effective_page_size items)
        if not data or len(data) < effective_page_size:
            break

        page += 1

    console.print(f"[green]Collected {len(cases)} cases.[/green]")
    return cases


# ----------------- Domain & WHOIS -----------------

STATUS_RE = re.compile(r"(client[\s-]?hold|server[\s-]?hold)", re.IGNORECASE)


def extract_registered_domain(url: str) -> Optional[str]:
    if not url:
        return None
    try:
        ext = tldextract.extract(url)
        if not ext.domain or not ext.suffix:
            return None
        return ext.registered_domain
    except Exception:
        return None


def parse_whois_output(whois_text: str) -> Tuple[Optional[str], Optional[str]]:
    """
    Returns (status_string, last_updated)
    - status_string: full line containing clientHold/serverHold (last occurrence)
    - last_updated: parsed from common WHOIS fields; None if not found
    """
    if not whois_text:
        return None, None

    # Collect all lines with hold status
    status_lines = []
    for line in whois_text.splitlines():
        if STATUS_RE.search(line):
            status_lines.append(line.strip())

    if not status_lines:
        return None, None

    # Use last occurrence – usually domain-level status
    status_string = status_lines[-1]

    updated_patterns = [
        r"Updated Date:\s*(.+)",
        r"Last Updated:\s*(.+)",
        r"Last Update:\s*(.+)",
        r"changed:\s*(.+)",
    ]

    last_updated = None
    for pat in updated_patterns:
        m = re.search(pat, whois_text, re.IGNORECASE)
        if m:
            last_updated = m.group(1).strip()
            break

    return status_string, last_updated


def run_whois(domain: str, timeout: int, verbose: bool) -> str:
    try:
        result = subprocess.run(
            ["whois", domain],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
        )
        if verbose and result.stderr:
            console.print(f"[yellow]WHOIS stderr for {domain}: {result.stderr}[/yellow]")
        return result.stdout
    except Exception as e:
        if verbose:
            console.print(f"[red]WHOIS failed for {domain}: {e}[/red]")
        return ""


def process_domain(
    domain: str, timeout: int, verbose: bool
) -> Tuple[str, Optional[str], Optional[str]]:
    """
    Returns (domain, last_updated, status_string)
    """
    text = run_whois(domain, timeout, verbose)
    status_string, last_updated = parse_whois_output(text)
    return domain, last_updated, status_string


# ----------------- Coloring & Plain Text -----------------


def highlight_status(status: Optional[str]) -> Text:
    """
    Colorizes variations of clientHold / serverHold for Rich table output.
    Plain text output remains unchanged elsewhere.
    """
    if not status:
        return Text("")

    txt = Text(status)

    highlights = [
        (re.compile(r"client[\s-]?hold", re.IGNORECASE), "bold bright_cyan"),
        (re.compile(r"server[\s-]?hold", re.IGNORECASE), "bold bright_red"),
    ]

    for pattern, style in highlights:
        for match in pattern.finditer(status):
            start, end = match.span()
            txt.stylize(style, start, end)

    return txt


def build_plain_text_table(rows: List[Tuple[str, Optional[str], Optional[str]]]) -> str:
    """
    Plain ASCII table for pasting into an email (no colors).
    """
    if not rows:
        return "No suspended domains found."

    col_widths = [
        max(len("Domain"), max(len(r[0]) for r in rows)),
        max(len("Last Updated"), max(len(r[1] or "") for r in rows)),
        max(len("Status"), max(len(r[2] or "") for r in rows)),
    ]

    def fw(text, w):
        return text.ljust(w)

    lines = []
    header = f"{fw('Domain', col_widths[0])} | {fw('Last Updated', col_widths[1])} | {fw('Status', col_widths[2])}"
    sep = "-" * len(header)
    lines.append(header)
    lines.append(sep)

    for d, u, s in rows:
        lines.append(
            f"{fw(d, col_widths[0])} | {fw(u or 'null', col_widths[1])} | {fw(s or '', col_widths[2])}"
        )

    return "\n".join(lines)


# ----------------- Main -----------------


def main():
    args = parse_args()
    verbose = args.verbose

    # Stage 0: login -> get authenticated session with cookies
    session = login(args.api_base, args.email, args.password, verbose)

    # Prepare base URL & params for /cases (with filters/search)
    base_url, base_params, effective_page_size = prepare_cases_url_and_params(
        args.api_base, args.per_page, verbose
    )

    # Stage 1: collect cases
    cases = collect_all_cases(
        session, base_url, base_params, effective_page_size, verbose
    )

    # Extract domains from cases
    unique_domains: List[str] = []
    for c in cases:
        url = c.get("url")
        domain = extract_registered_domain(url)
        if domain:
            unique_domains.append(domain)

    unique_domains = list(set(unique_domains))
    console.print(
        f"Discovered {len(unique_domains)} unique domains from {len(cases)} cases."
    )

    # Estimate time
    estimated = len(unique_domains) * ESTIMATED_SECS_PER_WHOIS
    if estimated > WARN_THRESHOLD_SECONDS:
        console.print(
            f"[bold red]WARNING: Estimated processing time ≈ {estimated/60:.1f} minutes (> 15 minutes).[/bold red]"
        )
        console.print(
            "[bold red]You may want to reduce domain count or increase threads.[/bold red]"
        )

    # Stage 2: WHOIS checks
    console.print("[bold]Stage 2: Running WHOIS checks[/bold]")

    results: List[Tuple[str, Optional[str], Optional[str]]] = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TimeElapsedColumn(),
        TimeRemainingColumn(),
        transient=False,
    ) as progress:
        task = progress.add_task("WHOIS lookups...", total=len(unique_domains))

        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            futures = {
                executor.submit(
                    process_domain, d, args.whois_timeout, verbose
                ): d
                for d in unique_domains
            }

            for future in as_completed(futures):
                domain = futures[future]
                try:
                    d, last_updated, status_string = future.result()
                    if status_string:
                        results.append((d, last_updated, status_string))
                except Exception as e:
                    if verbose:
                        console.print(f"[red]Error processing {domain}: {e}[/red]")
                progress.update(task, advance=1)

    # Stage 3: output
    console.print("[bold]Stage 3: Suspended Domains[/bold]")

    if results:
        results.sort(key=lambda x: x[0])

        # Rich table with colored status
        t = Table(show_header=True, header_style="bold magenta")
        t.add_column("Domain")
        t.add_column("Last Updated")
        t.add_column("Status")

        for d, u, s in results:
            t.add_row(d, u or "null", highlight_status(s))

        console.print(t)

        # Plain text (for email)
        console.print("\n[bold]Plain Text Table (for email):[/bold]")
        console.print(build_plain_text_table(results))
    else:
        console.print("[green]No suspended domains found.[/green]")

    # Stage 4: UI link
    console.print("\n[bold]Stage 4: UI Link[/bold]")
    console.print(
        f"View all suspended cases in UI: [blue]{args.ui_base}[/blue]  (replace with real link)"
    )

    console.print("\n[green]Done.[/green]")


if __name__ == "__main__":
    main()
