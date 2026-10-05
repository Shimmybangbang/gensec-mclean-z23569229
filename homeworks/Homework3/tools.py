"""Tools used by the Homework 3 multi-agent security analyst.

This module collects every tool the agents in ``app.py`` can call, grouped by
how far each one goes beyond the Lab 03 examples:

* **Retained lab tool** -- ``PythonREPLTool`` (required by the assignment),
  guarded by :data:`approve_python_middleware` so a human must approve every
  piece of code before it runs.
* **New built-in toolkit** -- LangChain's ``FileManagementToolkit``, sandboxed
  to the local ``workspace/`` directory so agents can read and write report
  files without touching the rest of the filesystem.
* **Custom tools** -- :func:`rag_search`, which queries the Chroma vector
  database built in Homework 2, and :func:`virustotal_lookup`, a
  Pydantic-schema tool that checks an IP, domain, URL, or file hash against
  the VirusTotal v3 API.

API keys are never stored in source: they are read from environment
variables (loaded from the repo root ``.env`` by ``app.py``).
"""

import base64
import ipaddress
import os
import re
from functools import lru_cache
from pathlib import Path
from typing import Literal

import requests
from langchain.agents.middleware import wrap_tool_call
from langchain.tools import tool
from langchain_community.agent_toolkits import FileManagementToolkit
from langchain_core.messages import ToolMessage
from langchain_experimental.tools import PythonREPLTool
from pydantic import BaseModel, Field

HW3_DIR = Path(__file__).resolve().parent

# The persisted Chroma database built by Homework 2's 07_rag_loaddb.py.
RAG_DB_DIR = HW3_DIR.parent / "Homework2" / "Lab02-RAG" / "rag_data" / ".chromadb"

# Sandbox directory for the file management tools.
WORKSPACE_DIR = HW3_DIR / "workspace"

VT_API_URL = "https://www.virustotal.com/api/v3"


# --------------------------------------------------------------------------
# Retained lab tool: Python REPL (with human approval)
# --------------------------------------------------------------------------

python_repl = PythonREPLTool()


@wrap_tool_call
def approve_python_middleware(request, handler):
    """Require human approval before the agent executes any Python code.

    ``PythonREPLTool`` runs arbitrary code on the host, so this middleware
    intercepts every ``Python_REPL`` call, shows the code, and only runs it if
    the user answers ``y``. Other tool calls pass straight through.

    Args:
        request: The pending tool call request from the agent.
        handler: Callback that actually executes the tool.

    Returns:
        The tool's ``ToolMessage``, or a ``ToolMessage`` telling the agent the
        user rejected the code.
    """
    call = request.tool_call
    if call["name"] != python_repl.name:
        return handler(request)

    print("\n🐍 The agent wants to run this Python code:\n")
    print(call["args"].get("query", call["args"]))
    answer = input("\nRun it? [y/N] ").strip().lower()
    if answer in ("y", "yes"):
        return handler(request)
    return ToolMessage(
        content="The user declined to run this code. Do not retry it; "
                "explain what you would have computed instead.",
        tool_call_id=call["id"],
        name=call["name"],
    )


# --------------------------------------------------------------------------
# New built-in toolkit: sandboxed file management
# --------------------------------------------------------------------------

def get_file_tools(selected: list[str] | None = None):
    """Return LangChain file management tools sandboxed to ``workspace/``.

    Args:
        selected: Names of the toolkit tools to include (for example
            ``["read_file", "list_directory"]``). Defaults to read, write and
            list.

    Returns:
        A list of ``BaseTool`` objects whose paths are confined to
        :data:`WORKSPACE_DIR`.
    """
    WORKSPACE_DIR.mkdir(exist_ok=True)
    return FileManagementToolkit(
        root_dir=str(WORKSPACE_DIR),
        selected_tools=selected or ["read_file", "write_file", "list_directory"],
    ).get_tools()


# --------------------------------------------------------------------------
# Custom tool: Homework 2 RAG database
# --------------------------------------------------------------------------

@lru_cache(maxsize=1)
def _get_vectorstore():
    """Open the Homework 2 Chroma database once and reuse it.

    Raises:
        FileNotFoundError: If Homework 2's loader has not been run yet.
    """
    if not RAG_DB_DIR.exists():
        raise FileNotFoundError(
            f"RAG database not found at {RAG_DB_DIR}. "
            "Run Homework2/Lab02-RAG/07_rag_loaddb.py first."
        )
    # Imported lazily so the app still starts if Chroma is unavailable.
    from langchain_chroma import Chroma
    from langchain_google_genai import GoogleGenerativeAIEmbeddings

    return Chroma(
        persist_directory=str(RAG_DB_DIR),
        embedding_function=GoogleGenerativeAIEmbeddings(
            model="models/gemini-embedding-001", task_type="retrieval_query"
        ),
    )


@tool
def rag_search(query: str) -> str:
    """Search my personal document database (built in Homework 2) and return
    the most relevant passages with their sources. The database includes the
    ITAR regulations (22 CFR Part 120 Subpart B), a Microsoft security
    report, the U.S. Constitution and amendments, a Python cheat sheet,
    Wikipedia pages on LangChain, and a few other documents. Use this for
    questions about any of those topics."""
    try:
        docs = _get_vectorstore().similarity_search(query, k=4)
    except Exception as e:
        return f"RAG search failed: {e}"
    if not docs:
        return "No relevant passages found."
    # Trim each chunk so four results fit comfortably in the model's context.
    return "\n\n---\n\n".join(
        f"[source: {doc.metadata.get('source', 'unknown')}]\n{doc.page_content[:2000]}"
        for doc in docs
    )


# --------------------------------------------------------------------------
# Custom tool: VirusTotal indicator lookup
# --------------------------------------------------------------------------

class VirusTotalInput(BaseModel):
    """Arguments for :func:`virustotal_lookup`."""

    indicator: str = Field(
        description="The indicator of compromise to check: an IPv4/IPv6 "
                    "address, a domain name, a full URL, or an MD5/SHA-1/"
                    "SHA-256 file hash."
    )
    indicator_type: Literal["auto", "ip", "domain", "url", "hash"] = Field(
        default="auto",
        description="Type of the indicator. Leave as 'auto' to detect it.",
    )


def _detect_indicator_type(indicator: str) -> str:
    """Guess whether an indicator is an IP, URL, file hash, or domain."""
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


@tool(args_schema=VirusTotalInput)
def virustotal_lookup(indicator: str, indicator_type: str = "auto") -> str:
    """Look up an IP address, domain, URL, or file hash on VirusTotal and
    report how many security vendors flag it as malicious, its reputation
    score, and related details. Use this to assess whether an indicator of
    compromise is known to be malicious."""
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    if not api_key:
        return "VIRUSTOTAL_API_KEY is not set in the environment."

    indicator = indicator.strip()
    kind = _detect_indicator_type(indicator) if indicator_type == "auto" else indicator_type
    if kind == "url":
        # VirusTotal identifies URLs by their unpadded URL-safe base64 encoding.
        object_id = base64.urlsafe_b64encode(indicator.encode()).decode().rstrip("=")
    else:
        object_id = indicator
    endpoint = {"ip": "ip_addresses", "domain": "domains", "url": "urls", "hash": "files"}[kind]

    try:
        resp = requests.get(
            f"{VT_API_URL}/{endpoint}/{object_id}",
            headers={"x-apikey": api_key},
            timeout=20,
        )
    except requests.RequestException as e:
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
    # Add the most useful type-specific fields when VirusTotal provides them.
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
