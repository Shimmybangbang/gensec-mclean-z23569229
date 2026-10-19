"""Homework 4: an MCP agent application.

A LangChain ``create_agent`` agent (Gemini) whose tools all come from two
Model Context Protocol servers, both launched as stdio subprocesses through
``langchain-mcp-adapters``' :class:`MultiServerMCPClient`:

* ``secintel`` -- the custom server in ``secintel_server.py`` (IOC
  extraction, NVD CVE lookup, VirusTotal, security-header grading, report
  saving, plus a triage prompt and report resources).
* ``fetch`` -- the official reference Fetch server
  (``mcp-server-fetch`` from github.com/modelcontextprotocol/servers),
  which downloads web pages and converts them to Markdown.

The agent coordinates tools from both servers to solve multi-step problems,
for example: fetch a published threat report, pull out its indicators, look
up every CVE and indicator, grade the publisher's site and save a report.

Usage::

    uv run app.py                 # interactive prompt; a blank line exits
    uv run app.py "question"      # answer one question and exit

Commands at the prompt::

    /tools             list every MCP tool and the server it came from
    /triage <url>      run the server's ``triage_threat_report`` prompt
    /reports [name]    list saved reports, or show one (MCP resources)

API keys are read from environment variables (loaded from the repo root
``.env``), never from source. Each server subprocess only receives the keys
it needs.
"""

import asyncio
import ipaddress
import os
import readline  # noqa: F401  (enables line editing/history in input())
import socket
import sys
from pathlib import Path
from urllib.parse import urlparse

from dotenv import load_dotenv
from langchain.agents import create_agent
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_mcp_adapters.client import MultiServerMCPClient
from langchain_mcp_adapters.interceptors import MCPToolCallRequest
from mcp.types import CallToolResult, TextContent

HW4_DIR = Path(__file__).resolve().parent

# Load the shared API keys/model names from the course repo root's .env file,
# two levels up from this script's directory.
load_dotenv(HW4_DIR.parents[1] / ".env")

SYSTEM_PROMPT = """You are a security analyst assistant. Your tools come from
two MCP servers:
- fetch: downloads a web page and returns it as Markdown.
- secintel: extract_iocs, lookup_cve, virustotal_lookup,
  check_security_headers and save_report.

Break multi-step requests into tool calls and chain their results: e.g.
fetch a page, pass its text to extract_iocs, then look up what you found.
Only state facts the tools returned, cite which tool they came from, and
defang malicious indicators in your answers (evil[.]com, hxxp://)."""


def env_subset(*names: str) -> dict[str, str]:
    """Build a minimal environment for an MCP server subprocess.

    Passes ``PATH`` and ``HOME`` plus only the named variables that are set,
    so a server never sees API keys it doesn't need.

    Args:
        *names: Environment variable names to forward.

    Returns:
        The environment mapping for the subprocess.
    """
    keep = ("PATH", "HOME", *names)
    return {k: os.environ[k] for k in keep if k in os.environ}


# Both servers run with this project's interpreter, so they use the versions
# pinned in uv.lock instead of whatever ``uvx`` would download at run time.
SERVERS = {
    "secintel": {
        "transport": "stdio",
        "command": sys.executable,
        "args": [str(HW4_DIR / "secintel_server.py")],
        "env": env_subset("VIRUSTOTAL_API_KEY", "NVD_API_KEY"),
    },
    "fetch": {
        "transport": "stdio",
        "command": sys.executable,
        "args": ["-m", "mcp_server_fetch"],
        "env": env_subset(),
    },
}


def is_public_url(url: str) -> bool:
    """Check that a URL resolves only to public (global) IP addresses.

    Args:
        url: The URL the agent wants to fetch.

    Returns:
        ``False`` for non-HTTP(S) URLs, unresolvable hosts, or any host that
        resolves to a loopback, private, link-local or reserved address.
    """
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return False
    try:
        infos = socket.getaddrinfo(parsed.hostname, parsed.port or 443)
    except socket.gaierror:
        return False
    return all(ipaddress.ip_address(info[4][0]).is_global for info in infos)


async def block_internal_fetches(request: MCPToolCallRequest, handler):
    """Tool-call interceptor that stops the Fetch server reaching internal hosts.

    The Fetch server will request any URL it is given, so a prompt-injected
    page could make the agent probe ``localhost`` or the LAN (SSRF). Every
    ``fetch`` call is checked with :func:`is_public_url` before it runs.

    Args:
        request: The pending MCP tool call.
        handler: Runs the tool call.

    Returns:
        The tool result, or an error result if the URL was blocked.
    """
    if request.server_name == "fetch":
        url = str(request.args.get("url", ""))
        if not await asyncio.to_thread(is_public_url, url):
            print(f"   ⛔ blocked fetch of non-public URL: {url}")
            return CallToolResult(
                content=[TextContent(type="text", text=f"Blocked: {url} is not a public http(s) URL.")],
                isError=True,
            )
    return await handler(request)


async def run_agent(agent, request: str) -> None:
    """Run the agent on one request, streaming tool calls and the answer.

    Args:
        agent: The compiled LangChain agent.
        request: The user's message.
    """
    async for update in agent.astream({"messages": [("user", request)]}, stream_mode="updates"):
        for step in update.values():
            for msg in step.get("messages", []):
                if msg.type == "ai" and msg.tool_calls:
                    for call in msg.tool_calls:
                        args = ", ".join(f"{k}={str(v)[:60]!r}" for k, v in call["args"].items())
                        print(f"🔧 {call['name']}({args})")
                elif msg.type == "tool":
                    preview = str(msg.content).replace("\n", " ")[:150]
                    print(f"   ↳ {preview}{'…' if len(str(msg.content)) > 150 else ''}")
                elif msg.type == "ai" and msg.text:
                    print(f"\n🤖 {msg.text}\n")


async def handle_command(line: str, client: MultiServerMCPClient, tools) -> str | None:
    """Handle a slash command typed at the prompt.

    Args:
        line: The input line, starting with ``/``.
        client: The connected MCP client.
        tools: The loaded MCP tools.

    Returns:
        A request to send to the agent (``/triage``), or ``None`` if the
        command was fully handled here.
    """
    cmd, _, arg = line.partition(" ")
    arg = arg.strip()
    if cmd == "/tools":
        for t in tools:
            print(f"  [{t.metadata.get('server', '?') if t.metadata else '?'}] {t.name}: "
                  f"{t.description.splitlines()[0]}")
    elif cmd == "/triage" and arg:
        messages = await client.get_prompt("secintel", "triage_threat_report", arguments={"url": arg})
        return messages[0].content
    elif cmd == "/reports":
        uri = f"secintel://reports/{arg}" if arg else "secintel://reports"
        blobs = await client.get_resources("secintel", uris=uri)
        print(blobs[0].as_string() if blobs else "(nothing)")
    else:
        print("Commands: /tools, /triage <url>, /reports [name]")
    return None


async def main() -> None:
    """Connect to both MCP servers, build the agent and run the chat loop."""
    client = MultiServerMCPClient(SERVERS, tool_interceptors=[block_internal_fetches])
    tools = []
    for server in SERVERS:
        server_tools = await client.get_tools(server_name=server)
        for t in server_tools:
            t.metadata = {**(t.metadata or {}), "server": server}
        tools += server_tools
    print(f"Connected to {len(SERVERS)} MCP servers, {len(tools)} tools: "
          + ", ".join(t.name for t in tools))

    llm = ChatGoogleGenerativeAI(model=os.getenv("GOOGLE_MODEL"))
    agent = create_agent(model=llm, tools=tools, system_prompt=SYSTEM_PROMPT)

    if len(sys.argv) > 1:
        await run_agent(agent, " ".join(sys.argv[1:]))
        return

    print("Ask a security question (blank line to exit). Commands: /tools, /triage <url>, /reports")
    while line := (await asyncio.to_thread(input, "\n>> ")).strip():
        request = await handle_command(line, client, tools) if line.startswith("/") else line
        if request:
            await run_agent(agent, request)


if __name__ == "__main__":
    asyncio.run(main())
