"""Homework 3: a LangGraph multi-agent security analyst.

Builds on the Lab 03 agent examples (``01_tools_python.py``,
``02_tools_builtin.py`` and ``06_langgraph_linux.py``) with a
supervisor/worker architecture:

* A **supervisor** node reads the user's request and the findings so far,
  then uses structured output to route the next step to one specialist
  worker, or to finish.
* Three **worker agents**, each a LangChain ``create_agent`` agent with its
  own tool set (see ``tools.py``):

  - ``researcher`` -- searches the Homework 2 RAG database and reads files in
    the sandboxed ``workspace/`` directory.
  - ``threat_intel`` -- checks IPs, domains, URLs and hashes on VirusTotal.
  - ``coder`` -- writes and runs Python with the PythonREPL tool (every run
    needs human approval) and can save results to ``workspace/``.

* A **responder** node writes the final answer from the collected findings.

Usage::

    uv run app.py            # interactive prompt; a blank line exits
    uv run app.py --graph    # also save the graph diagram to agent_graph.png

API keys are read from environment variables (loaded from the repo root
``.env``), never from source.
"""

import operator
import os
import readline  # noqa: F401  (enables line editing/history in input())
import sys
from pathlib import Path
from typing import Annotated, Literal

from dotenv import load_dotenv
from langchain.agents import create_agent
from langchain_google_genai import ChatGoogleGenerativeAI
from langgraph.graph import END, START, StateGraph
from pydantic import BaseModel, Field
from typing_extensions import TypedDict

# Load the shared API keys/model names from the course repo root's .env file,
# two levels up from this script's directory.
load_dotenv(Path(__file__).resolve().parents[2] / ".env")

from tools import (  # noqa: E402  (tools read env vars, so load .env first)
    approve_python_middleware,
    get_file_tools,
    python_repl,
    rag_search,
    virustotal_lookup,
)

llm = ChatGoogleGenerativeAI(model=os.getenv("GOOGLE_MODEL"))
#from langchain_openai import ChatOpenAI
#llm = ChatOpenAI(model=os.getenv("OPENAI_MODEL"))
#from langchain_anthropic import ChatAnthropic
#llm = ChatAnthropic(model=os.getenv("ANTHROPIC_MODEL"))

# Hard cap on worker turns per request so a confused supervisor can't loop.
MAX_WORKER_STEPS = 6


# --------------------------------------------------------------------------
# Worker agents
# --------------------------------------------------------------------------

WORKERS = {
    "researcher": {
        "description": "Answers questions from the user's personal document "
                       "database (ITAR regulations, a Microsoft security "
                       "report, the U.S. Constitution, a Python cheat sheet, "
                       "LangChain, etc.) and reads files in the workspace.",
        "tools": [rag_search, *get_file_tools(["read_file", "list_directory"])],
        "middleware": [],
        "prompt": "You are a research analyst. Use rag_search to find "
                  "relevant passages and cite the source of every fact you "
                  "report. If the database has nothing relevant, say so. "
                  "The file tools only see the separate workspace folder "
                  "(reports the team saved), not the database's sources.",
    },
    "threat_intel": {
        "description": "Checks IP addresses, domains, URLs, and file hashes "
                       "against VirusTotal to judge whether they are malicious.",
        "tools": [virustotal_lookup],
        "middleware": [],
        "prompt": "You are a threat intelligence analyst. Look up every "
                  "indicator you are given with virustotal_lookup and give a "
                  "short verdict (malicious / suspicious / clean / unknown) "
                  "for each, with the detection counts that support it.",
    },
    "coder": {
        "description": "Writes and runs Python code for calculations, data "
                       "processing, parsing logs, or encoding/decoding, and "
                       "saves output files to the workspace.",
        "tools": [python_repl, *get_file_tools(["write_file", "list_directory"])],
        "middleware": [approve_python_middleware],
        "prompt": "You are a Python engineer. Write and execute Python code "
                  "with the Python_REPL tool to answer the task, printing "
                  "the results you need. Only report results your code "
                  "actually produced. If the user declines to run the code, "
                  "stop and explain what it would have done.",
    },
}

worker_agents = {
    name: create_agent(
        model=llm,
        tools=spec["tools"],
        system_prompt=spec["prompt"],
        middleware=spec["middleware"],
        name=name,
    )
    for name, spec in WORKERS.items()
}


# --------------------------------------------------------------------------
# Graph state and routing schema
# --------------------------------------------------------------------------

class TeamState(TypedDict):
    """Shared state passed between the supervisor, workers and responder."""

    request: str
    findings: Annotated[list[str], operator.add]  # appended to by each worker
    next: str
    instructions: str
    steps: int
    answer: str


class Route(BaseModel):
    """The supervisor's decision about who acts next."""

    next: Literal["researcher", "threat_intel", "coder", "FINISH"] = Field(
        description="The worker to act next, or FINISH when the findings "
                    "are enough to answer the user's request."
    )
    instructions: str = Field(
        description="A specific, self-contained task for the chosen worker. "
                    "Empty when next is FINISH."
    )


# --------------------------------------------------------------------------
# Graph nodes
# --------------------------------------------------------------------------

def format_findings(findings: list[str]) -> str:
    """Render the findings list as a numbered block for prompts."""
    return "\n\n".join(f"{i}. {f}" for i, f in enumerate(findings, 1)) or "(none yet)"


def supervisor_node(state: TeamState) -> dict:
    """Pick the next worker (or FINISH) using structured LLM output.

    Args:
        state: The current team state.

    Returns:
        A state update with ``next`` and ``instructions`` set.
    """
    if state["steps"] >= MAX_WORKER_STEPS:
        print(f"🧭 Supervisor: step limit ({MAX_WORKER_STEPS}) reached, finishing.")
        return {"next": "FINISH", "instructions": ""}

    roster = "\n".join(f"- {name}: {spec['description']}" for name, spec in WORKERS.items())
    prompt = (
        "You are the supervisor of a small security-analysis team. Decide "
        "which worker should act next to satisfy the user's request, and "
        "give them a precise task. Delegate one step at a time; do not "
        "assign work that the findings already cover. Choose FINISH once "
        "the findings answer the request.\n\n"
        f"Workers:\n{roster}\n\n"
        f"User request:\n{state['request']}\n\n"
        f"Findings so far:\n{format_findings(state['findings'])}"
    )
    route = llm.with_structured_output(Route).invoke(prompt)
    print(f"🧭 Supervisor → {route.next}" + (f": {route.instructions}" if route.instructions else ""))
    return {"next": route.next, "instructions": route.instructions}


def make_worker_node(name: str):
    """Create a graph node that runs the named worker agent on its task.

    The worker sees only the original request, its instructions and prior
    findings, not the other workers' raw tool traffic. Tool calls and results
    are streamed to the console in the same style as the Lab 03 examples.

    Args:
        name: Key into :data:`WORKERS` / :data:`worker_agents`.

    Returns:
        A function suitable for ``StateGraph.add_node``.
    """
    agent = worker_agents[name]

    def worker_node(state: TeamState) -> dict:
        """Run the worker agent and record its final answer as a finding."""
        task = (
            f"Original user request: {state['request']}\n\n"
            f"Your task: {state['instructions']}\n\n"
            f"Findings from teammates so far:\n{format_findings(state['findings'])}"
        )
        final_text = ""
        for step in agent.stream({"messages": [{"role": "user", "content": task}]}):
            if "model" in step:
                message = step["model"]["messages"][-1]
                for tool_call in message.tool_calls:
                    print(f"   🛠️  [{name}] Tool Call: {tool_call['name']}   Args: {tool_call['args']}")
                if message.text:
                    final_text = message.text
            if "tools" in step:
                for message in step["tools"]["messages"]:
                    result = str(message.content)
                    print(f"   ✅ [{name}] Tool Result: {result[:400]}{'…' if len(result) > 400 else ''}")
        print(f"   📝 [{name}] {final_text[:300]}{'…' if len(final_text) > 300 else ''}")
        return {"findings": [f"[{name}] {final_text}"], "steps": state["steps"] + 1}

    return worker_node


def responder_node(state: TeamState) -> dict:
    """Write the final answer for the user from the team's findings."""
    response = llm.invoke(
        "Using only the findings below, write a clear, concise answer to the "
        "user's request. Keep source citations and VirusTotal detection "
        "counts where relevant. If the findings are incomplete, say what is "
        "missing.\n\n"
        f"User request:\n{state['request']}\n\n"
        f"Findings:\n{format_findings(state['findings'])}"
    )
    return {"answer": response.text}


def route_from_supervisor(state: TeamState) -> str:
    """Conditional edge: go to the chosen worker, or to the responder."""
    return "responder" if state["next"] == "FINISH" else state["next"]


# --------------------------------------------------------------------------
# Build the graph
# --------------------------------------------------------------------------

def build_graph():
    """Assemble and compile the supervisor/worker LangGraph.

    Returns:
        The compiled graph.
    """
    workflow = StateGraph(TeamState)
    workflow.add_node("supervisor", supervisor_node)
    for name in WORKERS:
        workflow.add_node(name, make_worker_node(name))
        workflow.add_edge(name, "supervisor")  # workers always report back
    workflow.add_node("responder", responder_node)

    workflow.add_edge(START, "supervisor")
    workflow.add_conditional_edges(
        "supervisor", route_from_supervisor, [*WORKERS, "responder"]
    )
    workflow.add_edge("responder", END)
    return workflow.compile()


def main():
    """Run the interactive command-line loop."""
    app = build_graph()

    if "--graph" in sys.argv:
        # Rendering uses the mermaid.ink web service.
        Path("agent_graph.png").write_bytes(app.get_graph().draw_mermaid_png())
        print("Graph saved to agent_graph.png")

    print("Welcome to my multi-agent security analyst. A supervisor routes your request to these agents:")
    for name, spec in WORKERS.items():
        print(f"  {name}: {', '.join(t.name for t in spec['tools'])}")
    print("Example prompts:")
    print("  Is 44d88612fea8a8f36de82e1278abb02f malicious, and what does ITAR say about defense articles?")
    print("  Base64-decode aHR0cDovL3d3dy5leGFtcGxlLmNvbQ== and check the result on VirusTotal")
    print("A blank line exits.")

    while True:
        try:
            line = input("llm>> ")
            if not line:
                break
            result = app.invoke(
                {"request": line, "findings": [], "next": "", "instructions": "", "steps": 0, "answer": ""},
                {"recursion_limit": 2 * MAX_WORKER_STEPS + 5},
            )
            print(f"\n💬 {result['answer']}\n")
        except (KeyboardInterrupt, EOFError):
            break
        except Exception as e:
            print(e)


if __name__ == "__main__":
    main()
