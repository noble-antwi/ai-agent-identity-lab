# 01. Agent from scratch: "Ask my SIEM"

**Status:** In progress. Stage 1a done, stage 1b under way.

## Goal

A Python agent I can ask plain questions about my lab, such as *"Is anything
unusual happening on WKS01 in the last 24 hours?"*, that answers only from what
its tools return. Two read-only tools: a search of Wazuh alerts on SIEM01, and a
lookup in the lab's Active Directory (`corp.biirabank.com`).

The project started as an AD + Okta lookup. It was re-scoped on 2026-10-13 to
Wazuh + AD because the Okta org has to be rebuilt first, and Wazuh already holds
real lab data worth asking about.

I am writing the agent loop by hand before using any framework. The point of
this lab is securing agents, and that needs a clear view of what an agent
actually is: a loop, a model, and a set of tools whose permissions are mine to
decide.

## Architecture

![Ask my SIEM data flow](images/agent-flow-animated.svg)

*One question in eight steps. Claude never connects to the lab: my code runs
every tool, under the agent's own read-only identity, and decides what Claude
gets to see. Static versions of both diagrams sit beside the animated ones in `images/`, and `images/build_animations.py` regenerates the motion from them.*

Three parts:

| Part | What it is | Here |
|---|---|---|
| The brain | Reads, reasons, decides which tool to ask for | Claude, through the Anthropic API |
| The loop | Ask the model; if it wants a tool, run it and hand back the result; repeat | `ask()` in `agent.py`, capped at 5 rounds |
| The tools | The only things the agent can touch | `search_wazuh_alerts` (stage 1), AD lookup (stage 2) |

## Design decisions

| Decision | Why | Control |
|---|---|---|
| The query is a fixed template in my code. Claude only fills the blanks (agent name, hours). | A model that writes its own queries can read anything the account can read. Filling blanks is the smallest useful power. | NIST 800-53 AC-6 least privilege |
| Tool inputs are checked by a strict schema and clamped in code (hours 1 to 24). | Never trust tool input, even from my own agent. | SI-10 input validation |
| The agent gets its own indexer account with a read-only role on `wazuh-alerts-*`, never `admin`. | Same pattern as the scanner's `svc-greenbone`: one identity per job, so every query is attributable and scoped. | AC-2, AC-6, IA-2 |
| The Wazuh indexer stays bound to `127.0.0.1`. The agent reaches it through an SSH tunnel. | Opening port 9200 to the network would let any lab host try credentials against the store of every log I collect. | SC-7 boundary protection, AC-17 remote access |
| The API key lives in a git-ignored `.env`, with a gitleaks pre-commit hook as backstop. | Moves to Vault in project 3. | IA-5 authenticator management |
| No tool can change anything. The answer ends with what a human should check. | Project 1 is read-only by rule. Write actions need an approval step, which comes later. | AC-6, AU-6 review by a human |

## Stages

| Stage | What | Status |
|---|---|---|
| 0 | Virtual environment, `anthropic` and `python-dotenv`, key in `.env` | Done 2026-10-13 |
| 1a | The loop by hand, with a fake Wazuh tool returning three made-up alerts | Done 2026-10-13 |
| 1b | Swap the fake tool for a real, read-only Wazuh query | In progress: tunnel, role, account and mapping proven; query code next |
| 2 | Add a read-only AD lookup tool | Not started |
| 3 | Move the loop to the Anthropic SDK's Tool Runner | Not started |

## How to run (stage 1a)

From Git Bash, inside this folder:

```bash
source .venv/Scripts/activate
python agent.py "Is anything unusual happening on WKS01 in the last 24 hours?"
```

`.env` beside `agent.py` must contain `ANTHROPIC_API_KEY=...`. It is never committed.

## Evidence

### Stage 1a: the loop works, and stays grounded

![First run of the agent](images/agent-01-first-run.png)

*Round 1 ends in `tool_use`: Claude asks for `search_wazuh_alerts` with WKS01
and 24 hours. My code runs it and sends back 622 characters. Round 2 ends in
`end_turn` with the report. Every claim cites the alert's time and rule id.*

The deletion test: I removed the `svc-greenbone` alert from the fake data and
ran it again. That finding vanished from the report entirely. The facts come
from the tool; the words come from the model. Whoever controls the tool
controls what the agent can know, so the tool and its account are the thing to
secure.

### Stage 1b: reaching the indexer without exposing it

![How the laptop reaches a database that only answers from inside](images/agent-doors-animated.svg)

*The indexer has no door on the network side. The laptop comes in through the
SSH door it already holds a key for, and sshd makes the call from inside
SIEM01, where the indexer does answer.*

![The Wazuh indexer listens on localhost only](images/agent-03-indexer-localhost-only.png)

*`ss -tlnp` on SIEM01: the indexer (`java`) listens on `[::ffff:127.0.0.1]:9200`,
which is 127.0.0.1 written in IPv6 form. A direct connection from the laptop is
refused, by design.*

![Through the tunnel, the indexer asks who I am](images/agent-04-tunnel-unauthorized.png)

*Through `ssh -N -L 9200:127.0.0.1:9200`, the laptop reaches the indexer, which
answers `Unauthorized` to a request with no login. The path works and the
door is still locked.*

![The agent's role: read on alerts, nothing else](images/agent-05-role-created.png)

*Role `agent-read-alerts` as saved: no cluster permissions, `read` on
`wazuh-alerts-*` only, no document or field restrictions yet, no tenants. The
archives index is not listed, so a request for it is refused by the indexer
whoever sends it.*

![Before mapping: the account is known but has no rights](images/agent-06-before-mapping-403.png)

*Before the role is mapped, `svc-ask-siem` with its correct password asks for
a count of alerts and gets `403` with `no permissions for
[indices:data/read/search]`, naming the user and `backend_roles=[]`. Compare
the `Unauthorized` (401) above: 401 means "I do not know who you are"
(authentication failed), 403 means "I know who you are, and the answer is no"
(authorization failed). The password never appears on the command line: curl
prompts for it.*

![The role mapped to the agent's account](images/agent-07-role-mapped.png)

*`svc-ask-siem` mapped directly as a user to `agent-read-alerts`. No backend
roles: the account lives only in the indexer.*

![After mapping: the same request succeeds](images/agent-08-after-mapping-count.png)

*The identical command after mapping returns `"count":460349` across 120
shards with none failed. Same account, same password, same question: the only
change is the role, so the role is what grants the access. 460,349 alerts is
also why the tool will never hand the model everything: it returns a capped,
filtered slice with a total.*

![The boundary holds: archives refused](images/agent-09-archives-denied-403.png)

*The same account, minutes later, asks to count `wazuh-archives-*` and gets
`403`. The archives hold every event Wazuh collects, not only the ones a rule
raised. The role names alerts only, so the boundary holds, whoever or whatever
is holding the password. `backend_roles=[]` is expected: the role is mapped to
the user directly, not through a backend role.*

## What I learned

- **An agent is three parts: a model, a loop, and tools.** The model never runs
  anything. It asks; my code decides whether to run it.
- **The agent only knows what its tools return.** Proven by the deletion test above.
- **An agent is only as good as its context.** It could not tell that
  `192.168.20.3` is my vulnerability scanner, so it could not explain a failed
  `administrator` logon as the scanner's default-credential check. That gap is
  why stage 2 adds an identity and asset lookup.
- **Agents over-claim.** Both runs ended by offering to search other machines.
  The script answers one question and stops. Check what an agent says it can do
  against the code.
- **A fast failure and a slow failure mean different things.** A refused
  connection in two seconds means the host answered "nothing here". A firewall
  drop hangs until it times out.

## What broke

![Running the script from the wrong folder](images/agent-02-wrong-folder.png)

*First attempts: stray characters pasted in front of the activate command, then
`python agent.py` run from the repo root, one folder above the script, so
Python could not find it.*

- Activation also failed once because the PowerShell form of the command was
  pasted into Git Bash, which needs `source .venv/Scripts/activate`.

- `curl https://192.168.20.2:9200` was refused. Not a network problem: the
  dashboard on port 443 answered over the same path. The indexer is bound to
  localhost, which led to the tunnel decision above.
