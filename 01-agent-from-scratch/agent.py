"""
Ask my SIEM, stage 1a: the agent loop written by hand, with a FAKE Wazuh tool.

The only thing this file sends over the network is the request to Claude.
The "Wazuh" tool below returns made-up alerts, so the loop can be learned
before any real lab system is touched. Stage 1b swaps the fake tool for a
real, read-only Wazuh query.

Run it:
    python agent.py "Is anything unusual happening on WKS01 in the last 24 hours?"
"""

import json
import sys

import anthropic
from dotenv import load_dotenv

# 1. Load the key from .env (the file beside this one) into the environment.
#    The client then picks it up by itself. The key never appears in this code.
load_dotenv()
client = anthropic.Anthropic()

MODEL = "claude-opus-5-5"
MAX_ROUNDS = 5  # A safety stop: the loop can never run forever (or cost forever).

# 2. The brief. This is how the agent is told to behave.
#    "Answer only from tool results" is what stops it inventing things.
SYSTEM = (
    "You are a security triage assistant for the Biira Bank lab. "
    "Answer only from what your tools return. When you make a claim, cite the "
    "alert it came from (time and rule id). If the data does not show something, "
    "say so plainly instead of guessing. You cannot change anything in the lab: "
    "finish with what a human analyst should check next."
)

# 3. The tool's description. This is all Claude ever sees of the tool: its name,
#    what it is for, and exactly what inputs it accepts. Claude never sees the
#    Python function below, and never runs it. Our code does.
TOOLS = [
    {
        "name": "search_wazuh_alerts",
        "description": (
            "Search recent Wazuh SIEM alerts for one lab machine. Read-only. "
            "Returns a list of alerts with time, rule id, level, description, "
            "account and source IP."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "agent_name": {
                    "type": "string",
                    "description": "The Wazuh agent name of the machine, e.g. WKS01",
                },
                "hours": {
                    "type": "integer",
                    "description": "How many hours back to search, from 1 to 24",
                },
            },
            "required": ["agent_name", "hours"],
            "additionalProperties": False,
        },
        "strict": True,  # Claude's inputs must match the schema exactly.
    }
]

# 4. The tool itself. FAKE for stage 1a: invented alerts, shaped like real ones.
#    One looks routine, one looks like the scanner, one should worry an analyst.
CANNED_ALERTS = [
    {"time": "2026-10-13T21:24:10Z", "agent": "WKS01", "rule_id": "60106", "level": 3,
     "description": "Windows Logon Success", "account": "jane.doe", "source_ip": "192.168.50.50"},
    {"time": "2026-10-13T21:26:02Z", "agent": "WKS01", "rule_id": "60122", "level": 5,
     "description": "Logon Failure - Unknown user or bad password",
     "account": "administrator", "source_ip": "192.168.20.3"},
    {"time": "2026-10-13T23:41:55Z", "agent": "WKS01", "rule_id": "100021", "level": 12,
     "description": "Scanner service account svc-greenbone authenticated from an unexpected source.",
     "account": "svc-greenbone", "source_ip": "192.168.50.99"},
]


def search_wazuh_alerts(agent_name: str, hours: int) -> list[dict]:
    """Stage 1a stub. Stage 1b replaces the body with a real read-only query."""
    hours = max(1, min(int(hours), 24))  # Never trust tool input blindly: clamp it.
    return [a for a in CANNED_ALERTS if a["agent"].lower() == agent_name.lower()]


def run_tool(name: str, tool_input: dict) -> tuple[str, bool]:
    """Our code, not Claude, decides what actually runs. Returns (result, is_error)."""
    if name == "search_wazuh_alerts":
        alerts = search_wazuh_alerts(tool_input["agent_name"], tool_input["hours"])
        return json.dumps(alerts), False
    return f"Error: there is no tool called {name}.", True


# 5. THE LOOP. Ask Claude; if it wants a tool, run it and hand back the result;
#    repeat until Claude gives a final answer.
def ask(question: str) -> None:
    messages = [{"role": "user", "content": question}]

    for round_no in range(1, MAX_ROUNDS + 1):
        response = client.beta.messages.create(
            model=MODEL,
            max_tokens=16000,
            system=SYSTEM,
            tools=TOOLS,
            messages=messages,
            output_config={"effort": "medium"},
            # If a safety check declines the request, retry it on another model
            # instead of just stopping. Security topics can trip those checks.
            betas=["server-side-fallback-2026-07-01"],
            fallbacks="default",
        )
        print(f"\n[round {round_no}] Claude stopped because: {response.stop_reason}")

        if response.stop_reason == "refusal":
            category = response.stop_details.category if response.stop_details else None
            print(f"Declined by a safety check (category: {category}).")
            return

        # Keep Claude's whole reply in the conversation, exactly as it came back.
        messages.append({"role": "assistant", "content": response.content})

        if response.stop_reason != "tool_use":
            answer = "".join(b.text for b in response.content if b.type == "text")
            print("\n========== Answer ==========\n" + answer)
            return

        # Claude asked for one or more tools. Run each, collect every result,
        # and send them all back together in one message.
        results = []
        for block in response.content:
            if block.type == "tool_use":
                print(f"[agent] Claude asked to run {block.name} with {block.input}")
                output, is_error = run_tool(block.name, block.input)
                print(f"[tool]  sent back {len(output)} characters")
                results.append({
                    "type": "tool_result",
                    "tool_use_id": block.id,  # Must match the request it answers.
                    "content": output,
                    "is_error": is_error,
                })
        messages.append({"role": "user", "content": results})

    print(f"\nStopped after {MAX_ROUNDS} rounds without a final answer.")


if __name__ == "__main__":
    question = " ".join(sys.argv[1:]) or "Is anything unusual happening on WKS01 in the last 24 hours?"
    ask(question)
