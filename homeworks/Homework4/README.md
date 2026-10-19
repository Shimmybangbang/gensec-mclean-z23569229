# Homework 4: MCP Security-Triage Agent

An agent application built on the Model Context Protocol (MCP). A LangChain
agent (Gemini) gets all of its tools from two MCP servers and chains them to
solve multi-step security problems, such as triaging a published threat report.

| Server | Origin | Tools / features |
| --- | --- | --- |
| `secintel` (`secintel_server.py`) | **Written for this homework** (FastMCP, stdio) | Tools: `extract_iocs`, `lookup_cve` (NIST NVD), `virustotal_lookup`, `check_security_headers`, `save_report`. Resources: `secintel://reports`, `secintel://reports/{name}`. Prompt: `triage_threat_report` |
| `fetch` (`mcp-server-fetch==2026.8.18`) | **Integrated** official reference server from [modelcontextprotocol/servers](https://github.com/modelcontextprotocol/servers/tree/main/src/fetch) | Tool: `fetch` (downloads a URL and converts it to Markdown) |

```
            ┌──────────── app.py ─────────────┐
 user ───►  │ create_agent (Gemini)           │
            │ MultiServerMCPClient            │
            │  └─ interceptor: block internal │
            └──────┬──────────────────┬───────┘
              stdio│                  │stdio
         ┌─────────▼───────┐  ┌───────▼────────┐
         │ secintel server │  │  fetch server  │
         │ NVD, VirusTotal │  │ (official ref) │
         └─────────────────┘  └────────────────┘
```

## Setup

```bash
cd homeworks/Homework4
uv sync                      # creates .venv from uv.lock
```

API keys are read from environment variables. `app.py` loads them from the
repo root `.env` file, which git ignores:

| Variable | Needed by |
| --- | --- |
| `GOOGLE_API_KEY`, `GOOGLE_MODEL` | the agent's LLM |
| `VIRUSTOTAL_API_KEY` | `secintel` → `virustotal_lookup` |
| `NVD_API_KEY` (optional) | `secintel` → `lookup_cve` (raises NVD's rate limit) |

Each server subprocess gets only `PATH`, `HOME` and the keys it needs. The
Fetch server gets no API keys at all.

## Running

```bash
uv run app.py                                  # interactive
uv run app.py "Is CVE-2024-3400 critical? Grade the headers on paloaltonetworks.com"
uv run mcp dev secintel_server.py              # test the custom server in MCP Inspector
```

Commands at the `>>` prompt:

- `/tools`: list every tool and the server it comes from
- `/triage <url>`: load the `triage_threat_report` **prompt** from the
  server and run it
- `/reports [name]`: read saved reports through the server's **resources**

### Example multi-step run

`/triage https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-158a`
makes the agent call:

1. `fetch` (Fetch server): downloads the CL0P/MOVEit advisory
2. `extract_iocs`: finds 2 CVEs, URLs, IPs and SHA-256 hashes
3. `lookup_cve` ×2: CVE-2023-34362 (9.8 critical) and CVE-2023-0669 (7.2 high)
4. `virustotal_lookup` ×5: all five indicators were flagged malicious
5. `check_security_headers`: cisa.gov scores a D (3 of 6 headers present)
6. `save_report`: writes [`workspace/triage.md`](workspace/triage.md)

## Verifying the integrated server is authentic

Malicious MCP servers are common (typosquatted packages, look-alike repos,
servers that exfiltrate env vars). Before installing `mcp-server-fetch` I
checked:

1. **Source repo.** It is in the official `modelcontextprotocol/servers`
   repository, the reference servers maintained by the MCP project
   (`src/fetch`). It is not a third-party fork or a marketplace re-upload.
2. **PyPI metadata.** The package `mcp-server-fetch` lists author
   *Anthropic, PBC*, uses the MIT license, and its Repository/Issues links
   point back to that GitHub repo.
3. **Build provenance.** PyPI's integrity API shows a Sigstore attestation
   for the pinned wheel. Its trusted publisher is GitHub,
   `modelcontextprotocol/servers`, workflow `release.yml`, environment
   `release`. So the wheel was built by the official repo's CI, not
   uploaded from someone's laptop:
   ```bash
   curl -s -H "Accept: application/vnd.pypi.integrity.v1+json" \
     https://pypi.org/integrity/mcp-server-fetch/2026.8.18/mcp_server_fetch-2026.8.18-py3-none-any.whl/provenance
   ```
4. **Version age.** A new version (2026.10.19) was published on the day I
   started. I pinned **2026.8.18** instead, which had been public for two
   months, so a compromised fresh release can't reach this project.
5. **Dependencies.** `httpx`, `markdownify`, `mcp`, `protego`, `pydantic`,
   `readabilipy` and `requests` are all well-known packages. `uv.lock`
   records the sha256 of every file (wheel `6642df73…`).
6. **No runtime download.** The server runs as `python -m mcp_server_fetch`
   from the locked venv instead of `uvx mcp-server-fetch`, which would
   resolve whatever version is newest at launch.

### Mitigating what the server can do

The Fetch server will request any URL, so a prompt-injected web page could
make the agent probe `localhost`, the LAN or cloud metadata endpoints (SSRF).
`app.py` registers a tool-call interceptor, `block_internal_fetches`. It
resolves every `fetch` URL and refuses it unless every address is a public
IP; `127.0.0.1` and `169.254.169.254` are both blocked. The server still
follows redirects itself, so a public URL that redirects to an internal one
is not covered. Running the server behind an egress proxy (`--proxy-url`)
would close that gap.

## Files

- `secintel_server.py`: the custom MCP server
- `app.py`: the agent application and MCP client configuration
- `workspace/`: reports saved by `save_report`
- `pyproject.toml`, `uv.lock`: dependencies managed with uv
