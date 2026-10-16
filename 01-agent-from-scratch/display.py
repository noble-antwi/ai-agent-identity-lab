"""
How the agent looks in the terminal. Nothing here changes what the agent does:
it only draws what agent.py tells it to, using the rich library.
"""

import json
import sys

from rich import box
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

# Windows terminals can default to an old encoding that cannot print symbols
# like ✓ and ⚙. Switch this program's output to UTF-8 so they always work.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

console = Console()

NAVY, CYAN, GREEN, AMBER, RED = "#1B2F5E", "#2DD4E8", "#3FB68B", "#E8A33D", "#E5604D"


def level_style(level: int) -> str:
    """Wazuh levels: 12+ is serious, 7+ worth a look, below that mostly routine."""
    if level >= 12:
        return f"bold {RED}"
    if level >= 7:
        return AMBER
    if level >= 4:
        return CYAN
    return "dim"


def header(question: str, model: str) -> None:
    title = Text("ASK MY SIEM", style=f"bold {CYAN}")
    body = Text.assemble(("Question  ", "dim"), (question, "bold white"),
                         ("\nModel     ", "dim"), (model, "white"),
                         ("\nTools     ", "dim"), ("search_wazuh_alerts (read-only, as svc-ask-siem)", "white"))
    console.print()
    console.print(Panel(body, title=title, title_align="left", border_style=CYAN, box=box.ROUNDED, padding=(1, 2)))


def thinking(round_no: int):
    """A live spinner while we wait for Claude. Use with `with`."""
    return console.status(f"[{CYAN}]Round {round_no}[/] · Claude is thinking...", spinner="dots")


def round_line(round_no: int, stop_reason: str) -> None:
    meaning = {
        "tool_use": "Claude ordered from the menu",
        "end_turn": "Claude wrote the answer",
        "max_tokens": "Claude ran out of room",
        "refusal": "a safety check declined",
    }.get(stop_reason, stop_reason)
    console.rule(Text.assemble((f"Round {round_no}", f"bold {CYAN}"), ("  ·  ", "dim"),
                               (meaning, "white"), (f"  ({stop_reason})", "dim")), style=NAVY)


def tool_call(name: str, tool_input: dict) -> None:
    blanks = "   ".join(f"[dim]{k}[/] [bold white]{v}[/]" for k, v in tool_input.items())
    console.print(f"  [{AMBER}]⚙[/]  [bold]{name}[/]   {blanks}")


def searching():
    return console.status(f"[{GREEN}]Searching Wazuh through the SSH tunnel...", spinner="dots")


def tool_result(output: str, is_error: bool) -> None:
    if is_error:
        console.print(Panel(output, title="Tool error, sent to Claude as is", border_style=RED,
                            box=box.ROUNDED, padding=(0, 2)))
        return

    result = json.loads(output)
    console.print(f"  [{GREEN}]✓[/]  Wazuh matched [bold]{result['total_matched']:,}[/] alerts on "
                  f"[bold]{result['agent_name']}[/] in the last {result['hours']}h · "
                  f"{len(result['summary_by_rule'])} rules · {result['alerts_shown']} examples "
                  f"· [dim]{len(output):,} characters to Claude[/]")

    table = Table(box=box.SIMPLE_HEAD, header_style=f"bold {CYAN}", padding=(0, 1), expand=False)
    table.add_column("Level", justify="right")
    table.add_column("Rule", style="dim")
    table.add_column("Description", max_width=60, overflow="ellipsis", no_wrap=True)
    table.add_column("Count", justify="right")
    for row in sorted(result["summary_by_rule"], key=lambda r: (-r["level"], -r["count"])):
        style = level_style(row["level"])
        table.add_row(Text(str(row["level"]), style=style), row["rule_id"],
                      Text(row["description"], style=style if row["level"] >= 7 else ""),
                      f"{row['count']:,}")
    console.print(table)


def answer(text: str, rounds: int, tokens_in: int, tokens_out: int) -> None:
    console.print()
    console.print(Panel(Markdown(text), title=Text("ANSWER", style=f"bold {GREEN}"), title_align="left",
                        border_style=GREEN, box=box.ROUNDED, padding=(1, 2)))
    console.print(f"[dim]  {rounds} rounds · {tokens_in:,} tokens in · {tokens_out:,} tokens out · "
                  f"facts from Wazuh, words from Claude[/]\n")


def refusal(category) -> None:
    console.print(Panel(f"Declined by a safety check (category: {category}).", border_style=RED))


def gave_up(max_rounds: int) -> None:
    console.print(Panel(f"Stopped after {max_rounds} rounds without a final answer.", border_style=AMBER))
