"""
Ask my SIEM, stage 3: the same agent on the Anthropic SDK's Tool Runner.

agent.py writes the loop by hand. Here the SDK runs it: tool_runner() asks
Claude, runs whichever tools Claude orders, sends the results back, and repeats
until Claude answers. What does NOT change is the kitchen: every tool still runs
through agent.run_tool(), so the clamping, the IP check, the allow-lists, the
secret filter and the safe error messages are exactly the ones stage 2 proved.

The menu card is the other big difference. agent.py writes the TOOLS list by
hand; here @beta_tool builds it from each function's name, type hints and
docstring. See what it built, and how it compares, with:
    python agent_runner.py --show-menu

Run it (same tunnel, same .env as agent.py):
    python agent_runner.py "Is anything unusual happening on WKS01 in the last 24 hours?"
"""

import json
import sys

from anthropic.lib.tools import ToolError, beta_tool

import agent  # The brief, the model, the client, and the kitchen (run_tool).


def kitchen(name: str, **tool_input) -> str:
    """Hand the order to the same kitchen agent.py uses. Errors stay our own words."""
    output, is_error = agent.run_tool(name, tool_input)
    if is_error:
        # Without this, the SDK would send Claude the raw Python exception text,
        # which can carry addresses and internals we chose not to share.
        raise ToolError(output)
    return output


# The menu card, written as Python. The docstring IS the description Claude
# reads, and each "Args:" line becomes that blank's description.
@beta_tool(strict=True)
def search_wazuh_alerts(agent_name: str, hours: int, source_ip: str) -> str:
    """Search Wazuh SIEM alerts for one lab machine over the last N hours (1 to 168, one week), optionally only those coming from one source IP address. Read-only. Returns the total number of matching alerts, a count per rule covering every match, and up to 40 example alerts, at most 2 per rule, newest first, so every rule is represented.

    Args:
        agent_name: The Wazuh agent name of the machine, e.g. WKS01
        hours: How many hours back to search, from 1 to 168 (one week)
        source_ip: Only alerts where the connection came from this IP address, e.g. 192.168.20.3. An empty string means any source.
    """
    return kitchen("search_wazuh_alerts", agent_name=agent_name, hours=hours, source_ip=source_ip)


@beta_tool(strict=True)
def lookup_host(host: str) -> str:
    """Identify a lab machine from its IP address or name. Read-only. Returns its entry in the lab inventory (name, network, OS, role, notes), the network an IP belongs to, and, if the machine joined the Windows domain, its Active Directory details (OU, OS, last logon).

    Args:
        host: An IP address (e.g. 192.168.20.3) or machine name (e.g. SCAN01)
    """
    return kitchen("lookup_host", host=host)


@beta_tool(strict=True)
def lookup_account(account: str) -> str:
    """Look up a Windows domain account in Active Directory. Read-only. Returns whether it exists and is enabled, user or computer, its OU, groups, description, and approximate last logon. Never returns secrets.

    Args:
        account: The account as it appears in alerts, e.g. svc-greenbone, CORP\\svc-greenbone, or a computer account like WKS01$
    """
    return kitchen("lookup_account", account=account)


TOOLS = [search_wazuh_alerts, lookup_host, lookup_account]


def text_of(content) -> str:
    """A tool result's content as plain text, whichever shape the SDK gives it."""
    if isinstance(content, str):
        return content
    return "".join(block.get("text", "") for block in content or [])


# The loop, now owned by the SDK. This function only watches it, and reports
# each step as the same events agent.run_agent() yields, so the terminal (and
# the web page) can show either version without knowing which one ran.
def run_agent(question: str):
    runner = agent.client.beta.messages.tool_runner(
        model=agent.MODEL,
        max_tokens=16000,
        system=agent.SYSTEM,
        tools=TOOLS,
        messages=[{"role": "user", "content": question}],
        output_config={"effort": "medium"},
        max_iterations=agent.MAX_ROUNDS,  # The same safety stop as the hand-written loop.
        betas=["server-side-fallback-2026-07-01"],
        fallbacks="default",
    )
    tokens_in = tokens_out = 0
    yield {"type": "thinking", "round": 1}

    for round_no, message in enumerate(runner, start=1):
        tokens_in += message.usage.input_tokens
        tokens_out += message.usage.output_tokens
        yield {"type": "round", "round": round_no, "stop_reason": message.stop_reason}

        if message.stop_reason == "refusal":
            category = message.stop_details.category if message.stop_details else None
            yield {"type": "refusal", "category": category}
            return
        if message.stop_reason != "tool_use":
            answer = "".join(b.text for b in message.content if b.type == "text")
            yield {"type": "answer", "text": answer, "rounds": round_no,
                   "tokens_in": tokens_in, "tokens_out": tokens_out}
            return

        names = {}
        for block in message.content:
            if block.type == "tool_use":
                names[block.id] = block.name
                yield {"type": "tool_call", "name": block.name, "input": block.input}
        # Runs the tools now, so we can show the results. The SDK keeps this
        # reply and sends it itself; the tools do not run a second time.
        response = runner.generate_tool_call_response()
        for result in response["content"] if response else []:
            yield {"type": "tool_result", "name": names.get(result["tool_use_id"], "?"),
                   "output": text_of(result.get("content")), "is_error": bool(result.get("is_error"))}
        yield {"type": "thinking", "round": round_no + 1}

    yield {"type": "gave_up", "max_rounds": agent.MAX_ROUNDS}


def show_menu() -> None:
    """Print the menu card @beta_tool built, beside the one written by hand in agent.py."""
    by_hand = {t["name"]: t for t in agent.TOOLS}
    for tool in TOOLS:
        built = tool.to_dict()
        print(f"\n=== {built['name']} ===")
        print(json.dumps(built, indent=2))
        hand = by_hand[built["name"]]
        # The SDK adds a "title" label to each blank. Harmless; ignore it, then compare.
        blanks = {k: {f: v for f, v in p.items() if f != "title"}
                  for k, p in built["input_schema"]["properties"].items()}
        checks = {
            "same blanks and types": blanks == hand["input_schema"]["properties"],
            "same required list": built["input_schema"]["required"] == hand["input_schema"]["required"],
            "extra blanks refused (additionalProperties false)":
                built["input_schema"].get("additionalProperties") is False,
            "strict": built.get("strict") is True,
            "same description": built["description"] == hand["description"],
        }
        for check, ok in checks.items():
            print(f"    {'OK  ' if ok else 'DIFF'} {check}")


if __name__ == "__main__":
    if sys.argv[1:] == ["--show-menu"]:
        show_menu()
    else:
        question = " ".join(sys.argv[1:]) or "Is anything unusual happening on WKS01 in the last 24 hours?"
        agent.ask(question, loop=run_agent)
