"""SecIntel: the custom MCP server written for Homework 4.

A small security-intelligence toolkit exposed over the Model Context Protocol
with the official Python SDK's ``FastMCP`` helper. It runs over stdio, so the
agent in ``app.py`` launches it as a subprocess.

Tools
    * :func:`extract_iocs` -- pull IPs, domains, URLs, file hashes, email
      addresses and CVE IDs out of free text (handles defanged indicators).
    * :func:`lookup_cve` -- fetch a CVE's description, CVSS score and
      weaknesses from the NIST National Vulnerability Database.
    * :func:`virustotal_lookup` -- check an IP, domain, URL or file hash on
      VirusTotal.
    * :func:`check_security_headers` -- grade a website's HTTP security
      response headers.
    * :func:`save_report` -- write a Markdown report into the sandboxed
      ``workspace/`` directory.

Resources
    * ``secintel://reports`` -- list of saved reports.
    * ``secintel://reports/{name}`` -- the contents of one saved report.

Prompts
    * :func:`triage_threat_report` -- step-by-step instructions for triaging
      a published threat report with every tool the agent has.

API keys (``VIRUSTOTAL_API_KEY``, optional ``NVD_API_KEY``) are read from
environment variables, never from source.

Usage::

    uv run secintel_server.py                       # stdio server
    uv run mcp dev secintel_server.py               # MCP Inspector UI
"""

import base64
import ipaddress
import os
import re
from pathlib import Path

import httpx
from mcp.server.fastmcp import FastMCP

WORKSPACE = Path(__file__).resolve().parent / "workspace"
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
VT_API_URL = "https://www.virustotal.com/api/v3"
USER_AGENT = "hw4-secintel-mcp/0.1"

mcp = FastMCP("secintel", log_level="WARNING")


# --------------------------------------------------------------------------
# Indicator helpers
# --------------------------------------------------------------------------

# Top-level domains accepted when extracting domains, to avoid matching file
# names such as "report.pdf" or "loader.exe" as domains.
COMMON_TLDS = {
    "com", "net", "org", "io", "info", "biz", "ru", "cn", "su", "top", "xyz",
    "online", "site", "club", "co", "us", "uk", "de", "fr", "nl", "jp", "kr",
    "in", "br", "tk", "ml", "ga", "cf", "gq", "pw", "cc", "me", "tv", "ws",
    "gov", "edu", "mil", "int", "app", "dev", "cloud", "link", "live", "shop",
}

IOC_PATTERNS = {
    "cves": re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE),
    "urls": re.compile(r"\b(?:https?|ftp)://[^\s<>\"')\]]+", re.IGNORECASE),
    "emails": re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b"),
    "ipv4": re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"),
    "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
    "sha1": re.compile(r"\b[a-fA-F0-9]{40}\b"),
    "md5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
    "domains": re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b", re.IGNORECASE),
}


def refang(text: str) -> str:
    """Undo common indicator defanging so the text can be parsed.

    Args:
        text: Text that may contain indicators like ``hxxp://evil[.]com``.

    Returns:
        The text with ``hxxp``, ``[.]``, ``(.)``, ``[dot]`` and ``[@]``
        replaced by their normal forms.
    """
    text = re.sub(r"\bhxxp", "http", text, flags=re.IGNORECASE)
    text = re.sub(r"\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)", ".", text, flags=re.IGNORECASE)
    text = re.sub(r"\[@\]|\[at\]", "@", text, flags=re.IGNORECASE)
    return text.replace("[:]", ":").replace("[://]", "://")


def detect_indicator_type(indicator: str) -> str:
    """Classify an indicator as ``ip``, ``url``, ``hash`` or ``domain``.

    Args:
        indicator: A refanged indicator string.

    Returns:
        The indicator type name.
    """
    try:
        ipaddress.ip_address(indicator)
        return "ip"
    except ValueError:
        pass
    if re.match(r"^[a-z][a-z0-9+.-]*://", indicator, re.IGNORECASE):
        return "url"
    if re.fullmatch(r"[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64}", indicator):
        return "hash"
    return "domain"


# --------------------------------------------------------------------------
# Tools
# --------------------------------------------------------------------------

@mcp.tool()
def extract_iocs(text: str) -> dict[str, list[str]]:
    """Extract indicators of compromise (IOCs) from free text.

    Finds CVE IDs, URLs, email addresses, IPv4 addresses, SHA-256/SHA-1/MD5
    hashes and domain names. Defanged indicators (``hxxp``, ``[.]``) are
    refanged first. Private/reserved IPs are dropped, and domains that only
    appear inside a URL or email address are not listed twice.

    Args:
        text: The text to scan, such as a threat report fetched from the web.

    Returns:
        A mapping of indicator type to a sorted list of unique indicators.
    """
    text = refang(text)
    found: dict[str, list[str]] = {}
    for kind, pattern in IOC_PATTERNS.items():
        matches = {m.group(0).rstrip(".,;:") for m in pattern.finditer(text)}
        if kind == "cves":
            matches = {m.upper() for m in matches}
        found[kind] = sorted(matches)

    found["ipv4"] = [ip for ip in found["ipv4"] if ipaddress.ip_address(ip).is_global]
    in_other = " ".join(found["urls"] + found["emails"]).lower()
    found["domains"] = [
        d for d in found["domains"]
        if d.lower().rsplit(".", 1)[-1] in COMMON_TLDS and d.lower() not in in_other
    ]
    return {kind: values for kind, values in found.items() if values}


@mcp.tool()
async def lookup_cve(cve_id: str) -> str:
    """Look up a CVE in the NIST National Vulnerability Database (NVD).

    Args:
        cve_id: A CVE identifier such as ``CVE-2021-44228``.

    Returns:
        A summary with the description, CVSS base score and severity,
        CWE weaknesses, publish date and up to five reference links.
    """
    cve_id = cve_id.strip().upper()
    if not re.fullmatch(r"CVE-\d{4}-\d{4,7}", cve_id):
        return f"'{cve_id}' is not a valid CVE ID (expected CVE-YYYY-NNNN)."

    headers = {"User-Agent": USER_AGENT}
    if api_key := os.getenv("NVD_API_KEY"):  # optional; raises the rate limit
        headers["apiKey"] = api_key
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(NVD_API_URL, params={"cveId": cve_id}, headers=headers)
    except httpx.HTTPError as e:
        return f"NVD request failed: {e}"
    if resp.status_code != 200:
        return f"NVD returned HTTP {resp.status_code} for {cve_id}."
    vulns = resp.json().get("vulnerabilities", [])
    if not vulns:
        return f"NVD has no record of {cve_id}."

    cve = vulns[0]["cve"]
    description = next(
        (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "n/a"
    )
    lines = [f"{cve_id} ({cve.get('vulnStatus', 'unknown status')})",
             f"  published: {cve.get('published', 'n/a')[:10]}",
             f"  description: {description}"]
    # Prefer the newest CVSS version NVD has scored.
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if metrics.get(key):
            data = metrics[key][0]["cvssData"]
            severity = data.get("baseSeverity") or metrics[key][0].get("baseSeverity", "")
            lines.append(f"  CVSS {data.get('version')}: {data.get('baseScore')} {severity}"
                         f" ({data.get('vectorString')})")
            break
    cwes = sorted({d["value"] for w in cve.get("weaknesses", []) for d in w.get("description", [])})
    if cwes:
        lines.append(f"  weaknesses: {', '.join(cwes)}")
    refs = [r["url"] for r in cve.get("references", [])[:5]]
    if refs:
        lines.append("  references: " + ", ".join(refs))
    return "\n".join(lines)


@mcp.tool()
async def virustotal_lookup(indicator: str) -> str:
    """Check an IP address, domain, URL or file hash on VirusTotal.

    Use this to judge whether an indicator of compromise is known to be
    malicious. The indicator type is detected automatically.

    Args:
        indicator: The indicator to look up (defanged forms are accepted).

    Returns:
        Detection counts, reputation and the main type-specific details.
    """
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    if not api_key:
        return "VIRUSTOTAL_API_KEY is not set in the environment."

    indicator = refang(indicator.strip())
    kind = detect_indicator_type(indicator)
    if kind == "url":
        # VirusTotal identifies URLs by their unpadded URL-safe base64 encoding.
        object_id = base64.urlsafe_b64encode(indicator.encode()).decode().rstrip("=")
    else:
        object_id = indicator
    endpoint = {"ip": "ip_addresses", "domain": "domains", "url": "urls", "hash": "files"}[kind]

    try:
        async with httpx.AsyncClient(timeout=20) as client:
            resp = await client.get(f"{VT_API_URL}/{endpoint}/{object_id}",
                                    headers={"x-apikey": api_key})
    except httpx.HTTPError as e:
        return f"VirusTotal request failed: {e}"
    if resp.status_code == 404:
        return f"VirusTotal has no record of {kind} '{indicator}'."
    if resp.status_code != 200:
        return f"VirusTotal returned HTTP {resp.status_code}: {resp.text[:300]}"

    attrs = resp.json().get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    lines = [
        f"VirusTotal report for {kind} '{indicator}':",
        f"  malicious: {stats.get('malicious', 0)}, suspicious: {stats.get('suspicious', 0)}, "
        f"harmless: {stats.get('harmless', 0)}, undetected: {stats.get('undetected', 0)}",
        f"  reputation: {attrs.get('reputation', 'n/a')}",
    ]
    for key in ("as_owner", "country", "registrar", "meaningful_name", "type_description", "title"):
        if attrs.get(key):
            lines.append(f"  {key}: {attrs[key]}")
    if attrs.get("tags"):
        lines.append(f"  tags: {', '.join(attrs['tags'][:10])}")
    flagged = [
        f"{engine} ({result.get('result')})"
        for engine, result in attrs.get("last_analysis_results", {}).items()
        if result.get("category") == "malicious"
    ]
    if flagged:
        lines.append(f"  flagged by: {', '.join(flagged[:10])}")
    return "\n".join(lines)


# Recommended security headers and what each one protects against.
SECURITY_HEADERS = {
    "strict-transport-security": "forces HTTPS (HSTS), blocks SSL-stripping",
    "content-security-policy": "restricts script/content sources, mitigates XSS",
    "x-content-type-options": "stops MIME sniffing (should be 'nosniff')",
    "x-frame-options": "blocks clickjacking via framing",
    "referrer-policy": "limits referrer leakage",
    "permissions-policy": "restricts browser features (camera, geolocation, ...)",
}

# Headers that disclose server software and versions to attackers.
DISCLOSURE_HEADERS = ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version")


@mcp.tool()
async def check_security_headers(url: str) -> str:
    """Grade a website's HTTP security response headers.

    Sends one GET request (following redirects) and checks for the six
    recommended security headers, plus headers that leak server software
    versions, which can then be looked up for known CVEs.

    Args:
        url: The page to check, e.g. ``https://example.com``.

    Returns:
        A letter grade (A-F), the present and missing headers, and any
        information-disclosure headers.
    """
    if not re.match(r"^https?://", url, re.IGNORECASE):
        url = "https://" + url
    try:
        async with httpx.AsyncClient(timeout=20, follow_redirects=True,
                                     headers={"User-Agent": USER_AGENT}) as client:
            resp = await client.get(url)
    except httpx.HTTPError as e:
        return f"Request to {url} failed: {e}"

    present = [h for h in SECURITY_HEADERS if h in resp.headers]
    missing = [h for h in SECURITY_HEADERS if h not in resp.headers]
    grade = "ABCDF"[min(len(missing), 4)]  # one letter lower per missing header
    lines = [f"Security headers for {resp.url} (HTTP {resp.status_code}): grade {grade}",
             f"  present ({len(present)}/{len(SECURITY_HEADERS)}):"]
    lines += [f"    {h}: {resp.headers[h][:120]}" for h in present] or ["    (none)"]
    lines.append("  missing:")
    lines += [f"    {h} -- {SECURITY_HEADERS[h]}" for h in missing] or ["    (none)"]
    disclosed = [f"{h}: {resp.headers[h]}" for h in DISCLOSURE_HEADERS if h in resp.headers]
    if disclosed:
        lines.append("  information disclosure: " + "; ".join(disclosed))
    if resp.url.scheme != "https":
        lines.append("  WARNING: final page was served over plain HTTP.")
    return "\n".join(lines)


@mcp.tool()
def save_report(filename: str, content: str) -> str:
    """Save a Markdown report to the sandboxed ``workspace/`` directory.

    Args:
        filename: A bare file name such as ``triage.md``. Directories are
            stripped so the report can't be written outside the workspace.
        content: The Markdown text of the report.

    Returns:
        A confirmation with the saved path and size.
    """
    name = Path(filename).name
    if not name or name.startswith("."):
        return f"Invalid file name '{filename}'."
    if not name.endswith(".md"):
        name += ".md"
    WORKSPACE.mkdir(exist_ok=True)
    path = WORKSPACE / name
    path.write_text(content, encoding="utf-8")
    return f"Saved report to workspace/{name} ({len(content)} characters)."


# --------------------------------------------------------------------------
# Resources
# --------------------------------------------------------------------------

@mcp.resource("secintel://reports")
def list_reports() -> str:
    """List the Markdown reports saved in the workspace, one per line."""
    reports = sorted(p.name for p in WORKSPACE.glob("*.md")) if WORKSPACE.exists() else []
    return "\n".join(reports) or "(no reports saved yet)"


@mcp.resource("secintel://reports/{name}")
def read_report(name: str) -> str:
    """Return the contents of one saved report.

    Args:
        name: The report's file name, as listed by ``secintel://reports``.
    """
    path = WORKSPACE / Path(name).name
    if not path.is_file():
        return f"No report named '{name}'."
    return path.read_text(encoding="utf-8")


# --------------------------------------------------------------------------
# Prompts
# --------------------------------------------------------------------------

@mcp.prompt()
def triage_threat_report(url: str, report_name: str = "triage.md") -> str:
    """Instructions for triaging a published threat report end to end.

    Args:
        url: Where the threat report or security advisory is published.
        report_name: File name for the saved triage report.
    """
    return f"""Triage the threat report published at {url}. Work step by step:

1. Use the `fetch` tool to download the report. If it is long, keep fetching
   with a larger `start_index` until you have the whole article.
2. Run `extract_iocs` on the article text.
3. For every CVE found (up to 5), call `lookup_cve` to get its severity.
4. For the most important network indicators and hashes (up to 5), call
   `virustotal_lookup` and record a verdict: malicious / suspicious /
   clean / unknown.
5. Run `check_security_headers` on the site that published the report.
6. Write a Markdown report with: a 3-sentence summary, a CVE table
   (ID, CVSS, severity, one-line description), an IOC table (indicator,
   type, verdict, detections), the header grade, and recommended actions.
   Defang every malicious indicator in the report (e.g. evil[.]com).
7. Save it with `save_report` as `{report_name}` and tell me what you found.

Only report facts the tools actually returned."""


if __name__ == "__main__":
    mcp.run()  # stdio transport
