# 01. Ask my SIEM: an AI agent with its own identity

**Status:** working end to end against a real SIEM. Stage 2 built: the agent can
now look up machines and accounts, signing in to Active Directory over LDAPS as
itself. Next: the same agent on the SDK's Tool Runner (stage 3).

![A real question, start to finish, at twice the speed](images/agent-15-web-run.gif)

*A real run against the lab's Wazuh SIEM, at twice the speed. The shield turns
green while Wazuh is searched, gold while Claude writes, and draws a check when
the answer is ready. Full run at normal speed:
[YouTube](https://youtu.be/wKmEA8ltwyM).*

## In 30 seconds

I can ask my security lab a plain question, such as *"Is anything unusual
happening on WKS01 in the last 24 hours?"*, and an AI agent answers it from my
SIEM's real alerts, citing the rule and time behind every claim.

The interesting part is not that it answers. It is **how little the AI is
trusted while it does**:

- **The AI never touches the lab.** Claude only asks for a search. My code runs
  it, under a separate account, and decides what Claude gets to see.
- **The agent has its own identity.** It searches as `svc-ask-siem`, an account
  with one read-only role on alerts and nothing else. Proven: before the role was
  granted the account got `403`, after it got data, and the archive of every raw
  event still returns `403`.
- **It cannot write its own queries.** The search is a fixed template; Claude
  only fills in two blanks, the machine and the time window.
- **It knows what it is looking at.** It can ask *"what is 192.168.20.3?"* and
  *"who is svc-greenbone?"*. Machines come from the lab inventory, accounts from
  Active Directory, read over LDAPS by the agent's own AD account.
- **Secrets are stripped before anything leaves.** Command lines and AD
  descriptions pass through a filter that removes passwords, keys and tokens,
  proven on 18 test cases.
- **It checks who it is talking to.** The connection to the SIEM verifies the
  server's certificate, so nothing can impersonate the SIEM and feed it fake
  alerts.
- **It says what it does not know.** With the SIEM unreachable, it refused to
  guess. On another run it spotted that its own tool's numbers did not add up,
  which exposed a real bug.

## How it works

![How one question becomes an answer](images/agent-flow-animated.svg)

*One question in eight steps. Claude never connects to the lab: my code runs
every tool, under the agent's own read-only identity, and decides what Claude
gets to see.*

An agent is three parts, and I wrote the loop by hand before using any framework
so that none of it is magic:

| Part | What it is | Here |
|---|---|---|
| The brain | Reads, reasons, decides which tool to ask for | Claude, through the Anthropic API |
| The loop | Ask the model; if it wants a tool, run it and hand back the result; repeat | `run_agent()` in `agent.py`, capped at 8 rounds |
| The tools | The only things the agent can touch | `search_wazuh_alerts`, `lookup_host`, `lookup_account`, all read-only |

**One agent, two faces.** The loop lives once, in `agent.run_agent()`, and
reports each step as an event. The terminal version and the web page both draw
the same events, so the agent cannot behave differently depending on how it is
shown.

### Reaching the SIEM without exposing it

![How the laptop reaches a database that only answers from inside](images/agent-doors-animated.svg)

*The Wazuh database has no door on the network side, and it stays that way. The
laptop comes in through the SSH door it already holds a key for, and the call is
made from inside SIEM01, where the database does answer.*

## Design decisions

| Decision | Why | Control |
|---|---|---|
| The query is a fixed template in my code. Claude only fills the blanks (machine, hours). | A model that writes its own queries can read anything the account can read. Filling blanks is the smallest useful power. | NIST 800-53 AC-6 least privilege |
| Tool inputs are checked by a strict schema and clamped in code (1 to 168 hours, one week). | Never trust tool input, even from my own agent. | SI-10 input validation |
| The agent has its own indexer account with a read-only role on `wazuh-alerts-*`, never `admin`. | One identity per job, the same pattern as the lab's scanner account: every query is attributable and scoped. | AC-2, AC-6, IA-2 |
| The Wazuh indexer stays bound to `127.0.0.1`. The agent reaches it through an SSH tunnel. | Opening port 9200 to the network would let any lab host try passwords against the store of every log I collect. | SC-7 boundary protection, AC-17 remote access |
| The certificate is checked against Wazuh's own CA, at `127.0.0.1`, the only address on it. No verification turned off. | An agent that skips the check can be fed fake alerts and would report them as fact. Proven both ways: the real certificate passes, `localhost` is rejected with a hostname mismatch. | SC-8, SC-23 session authenticity |
| Only named fields leave the lab: who, where, which rule, which program ran (`image`), what started it (`parentImage`), which file was written (`targetFilename`). Command lines are sent only after `redact.py` strips passwords, keys, tokens and encoded payloads and cuts them to 300 characters (`test_redact.py`, 14 cases). The raw log line never leaves. Results are capped at 50 alerts plus a per-rule count of every match. | Whatever a tool returns goes to the model provider. Paths name things; command lines are free text and can hold secrets or attacker-chosen instructions. Send the least that answers the question, and clean what must be sent. | AC-4 information flow, SC-28, SI-10, SA-8 |
| The system prompt says text inside alerts is data, never instructions. | Log fields can contain attacker-chosen text. This is the first, weakest layer against prompt injection; project 9 tests it properly. | SI-10 |
| No tool can change anything. Every answer ends with what a human should check. | Project 1 is read-only by rule. Write actions will need an approval step. | AC-6, AU-6 |
| The API key and the agent's passwords live in a git-ignored `.env`, with a gitleaks pre-commit hook as backstop. | Moves to Vault in project 3. | IA-5 |
| In AD the agent is a separate account, `svc-ask-siem`: Domain Users only, marked sensitive so no service can borrow its identity. Same name as its Wazuh login, separate password. | One name per actor: wherever `svc-ask-siem` shows up in a log, it is the agent. Read access needs no grant, because any signed-in account can read most of AD. | AC-2, AC-6, IA-2 |
| AD is reached over LDAPS (636), never plain LDAP (389), and DC01's certificate is checked against the lab's own root CA, by name. | On 389 the agent's password would cross the network readable. An unchecked certificate would let anything pretend to be DC01. | SC-8, SC-23, IA-5 |
| The lookups read named attributes only (`ACCOUNT_ATTRIBUTES`, `HOST_ATTRIBUTES`). | AD will not limit what a signed-in account reads, so the tool must. Attributes that hold secrets (LAPS passwords, BitLocker recovery keys) are never asked for, so they cannot leak even if AD permissions are one day set wrong. | AC-4, AC-6 |
| Account names are checked against a strict pattern, then escaped before they go into an LDAP filter. `*` is refused. | LDAP injection: an unescaped `*` would match every account in the domain. | SI-10 |
| Machines come from a hand-kept inventory, `assets.json`, plus AD for domain-joined Windows machines. | Most of the lab is Linux or appliances that AD has never heard of, and AD stores no IP addresses. Real companies keep this in a CMDB. | CM-8 component inventory |

### The web page is a new door, so it is built like one

| Control | Why |
|---|---|
| Listens on `127.0.0.1` only | Nothing else on the network can reach it |
| A random token, new at every start, is required on every request | Another web page open in the same browser cannot quietly make the agent run, and spend |
| Host header pinned to `127.0.0.1` / `localhost` | Blocks DNS rebinding, where a hostile site points its own name at your laptop |
| Strict Content-Security-Policy, no third-party script at all | The page can run only its own code |
| Data from Wazuh and Claude is inserted as text, never as HTML; the answer's Markdown goes through a renderer that escapes everything first | Alert fields can hold attacker-chosen text, and it must never become live markup |
| `Referrer-Policy: no-referrer` | The token never leaks to another site |

## Evidence

### The loop works, and stays grounded

![First run of the agent](images/agent-01-first-run.png)

*First run, against a fake Wazuh tool. Round 1: Claude asks for
`search_wazuh_alerts` with WKS01 and 24 hours; my code runs it. Round 2: the
report, citing time and rule id for every claim.*

The deletion test: I removed one alert from the fake data and ran it again. That
finding vanished from the report entirely. The facts come from the tool; the
words come from the model. Whoever controls the tool controls what the agent can
know, so the tool and its account are the thing to secure.

### The agent's identity, proven step by step

![The Wazuh indexer listens on localhost only](images/agent-03-indexer-localhost-only.png)

*`ss -tlnp` on SIEM01: the indexer listens on `[::ffff:127.0.0.1]:9200`, which
is 127.0.0.1 written in IPv6 form. A direct connection from the laptop is
refused, by design.*

![Through the tunnel, the indexer asks who I am](images/agent-04-tunnel-unauthorized.png)

*Through the SSH tunnel the laptop reaches the indexer, which answers
`Unauthorized` to a request with no login. The path works and the door is still
locked.*

![The agent's role: read on alerts, nothing else](images/agent-05-role-created.png)

*Role `agent-read-alerts`: no cluster permissions, `read` on `wazuh-alerts-*`
only, no tenants. The archives are not listed, so a request for them is refused
whoever sends it.*

![Before mapping: the account is known but has no rights](images/agent-06-before-mapping-403.png)

*Before the role is mapped: `svc-ask-siem`, with its correct password, gets
`403 no permissions for [indices:data/read/search]`. 401 means "I do not know who
you are"; 403 means "I know who you are, and the answer is no". The password
never appears on the command line: curl prompts for it.*

![The role mapped to the agent's account](images/agent-07-role-mapped.png)

*`svc-ask-siem` mapped directly to `agent-read-alerts`.*

![After mapping: the same request succeeds](images/agent-08-after-mapping-count.png)

*The identical command after mapping returns `"count":460349`. Same account,
same password, same question: the only change is the role, so the role is what
grants the access. 460,349 alerts is also why the tool never hands the model
everything.*

![The boundary holds: archives refused](images/agent-09-archives-denied-403.png)

*Minutes later, the same account asks for the archives, which hold every raw
event, and gets `403`. The boundary holds whoever, or whatever, holds the
password.*

![The laptop verifies the indexer's certificate](images/agent-10-tls-verified-401.png)

*No `-k`: the certificate is checked against Wazuh's CA, at the one address
printed on it. Getting a reply at all is the proof the check passed.*

### It fails honestly

![The agent fails honestly when Wazuh is unreachable](images/agent-11-tunnel-down-no-guessing.png)

*The first real run happened with the tunnel closed. The agent said it could not
answer rather than inventing a picture of WKS01: "I have no alerts, rule counts
or timestamps to cite, so I won't guess." It retried once, a wasted round, so the
error text now tells it that retrying will not help until a human fixes the
connection.*

### The first real run

![Round 1: the real search](images/agent-12-first-real-run-search.png)

*Claude fills the two blanks. The tool searches as `svc-ask-siem` through the
tunnel, finds 694 alerts across 17 rules, and sends Claude a per-rule count of
all 694 plus the 50 highest-level alerts: 14,481 characters, not 694 raw
events.*

![Round 2: the answer](images/agent-13-first-real-run-answer.png)

*The answer separates what it saw (50 alerts) from what it only counted (all
694), cites rule and time for every claim, and labels its one timing-based
inference as a guess.*

![The hand-off to a human](images/agent-14-first-real-run-next-steps.png)

*It ends with what a human should check, and changes nothing. Two rounds, about
10,000 tokens.*

### Checking the agent's work

An agent's answer is a junior analyst's report: every claim is checked before
anyone acts on it. First claim checked: "rule 92058 fired every hour at about
:40".

![Rule 92058 in Discover: 24 hits, one per hour](images/agent-16-human-check-92058.png)

*24 hits, one per hour at about :40. The claim holds. The full event also showed
what the agent could not see at the time: the program is
`C:\Windows\System32\sdbinst.exe`, started by the built-in Program Compatibility
Assistant service (`svchost.exe ... -s PcaSvc`). Windows' own scheduled
behaviour, not an attacker, so the level 12 rating is very likely a false
positive.*

That check led to a decision: send the agent the program paths, and the command
lines through the secret filter. The same question afterwards, nothing else
changed:

| | Before (rule names and times only) | After (paths and cleaned command lines) |
|---|---|---|
| Rule 92058, level 12, hourly | "Worth identifying what triggers it" | `sdbinst.exe -m -bg` started by `svchost.exe ... -s PcaSvc`: "fits normal Windows behaviour" |
| Rule 92217, executables in the Windows folder | No explanation possible | `AM_Delta_Patch_...exe` written by `svchost.exe` to `SoftwareDistribution\Download\Install`: Defender definition updates |
| Rule 92212, level 14 | Likely false alarm, from the filename alone | Same verdict, now naming the writing process, 32-bit PowerShell |

Second claim checked: "the local Administrators group changed 14 times, about
1 hour 41 minutes apart; the alerts don't say who made the change". The agent
was right that it could not tell, and right to send it to a human.

![Rule 60147 in Discover: the machine changed its own group](images/agent-17-human-check-60147.png)

*Every change was made by `WKS01$` (`S-1-5-18`, Local System, logon session
`0x3e7`): the computer itself, not a person. The group is the built-in
Administrators (`S-1-5-32-544`). Group Policy refreshes every 90 minutes plus a
random 0 to 30, and the lab's own Group Policy Preference adds the scanner's
group to local Administrators on every refresh, which Windows records as a group
change each time. Explained: expected behaviour from the lab's own policy.*

Third pattern, the bursts at 00:39 and 12:39 (PowerShell writing files and
running `SecEdit.exe`): traced up the process tree to
`C:\Program Files (x86)\ossec-agent\wazuh-agent.exe`. The SIEM's own agent,
running its twice-daily security configuration check, was setting off the SIEM's
own alerts.

### Stage 2: a second identity, in Active Directory

The first real run could not say that `192.168.20.3` is the lab's own scanner.
Stage 2 gives the agent context: who an account is, and what a machine is.

The agent gets its own AD account, in the service accounts OU beside the
scanner's:

![The agent's AD account in BIIRA/Users/ServiceAccounts](images/agent-18-ad-account-in-ou.png)

*`svc-ask-siem` sits beside `svc-greenbone`: one account per non-human job.*

![The new account checked from PowerShell](images/agent-19-ad-account-verified.png)

*Enabled, in the right OU, and `AccountNotDelegated: True` (sensitive, cannot be
delegated). `MemberOf` is empty: no groups beyond Domain Users, which AD never
lists there.*

Before any of it went into the agent, a small script, `ldap_check.py`, signed in
as that account over LDAPS:

![Signed in over LDAPS as the agent, TLS 1.3](images/agent-20-ldaps-signin-as-agent.png)

*TLS 1.3, and DC01 confirms the caller: `u:CORP\svc-ask-siem`, the agent and
nobody else. The "last logon" is this very sign-in, recorded under the agent's
own name. (First version of the script; it now prints exactly what Claude would
receive.)*

![The same account reading the domain's built-in Administrator](images/agent-21-any-account-reads-ad.png)

*The same account, with no groups and no grants, reading the domain's built-in
`Administrator`: where it lives, when it last signed in, and its group list
(blurred here). Any signed-in account can map who holds power in AD. That is
why the agent's tool, not AD, decides which attributes it reads.*

Then the two tools, called directly with no AI involved:

| Call | What came back |
|---|---|
| `lookup_host("192.168.20.3")` | SCAN01, the Greenbone scanner on the BlueTeam VLAN, which runs authenticated scans as `svc-greenbone`. Not domain-joined |
| `lookup_host("WKS01")` | Inventory entry plus AD: domain-joined, in `BIIRA/Computers/Workstations`, Windows 11 Pro |
| `lookup_host("192.168.50.77")` | Not in the inventory, but on the EnterpriseLAN VLAN, where workstations get DHCP addresses |
| `lookup_account("svc-greenbone")` | Enabled user in `BIIRA/Users/ServiceAccounts`, member of `SG-Scanner-LocalAdmin`, sensitive |
| `lookup_account("CORP\WKS01$")` | A computer account, primary group Domain Computers |
| `lookup_account("*")` | Refused: not a valid account name. No search was run |

### Stage 2, first agent run: it named the scanner

The question run one could not answer: *"Who or what is 192.168.20.3, and what
has it been doing on WKS01 this week?"*

![Round 1: two tools at once](images/agent-23-stage2-lookups-and-search.png)

*Round 1: Claude ordered two tools in one round, the machine lookup and the
alert search, because neither depended on the other. 192.168.20.3 comes back as
SCAN01, the Greenbone scanner.*

![The answer, with every fact's source named](images/agent-24-stage2-answer.png)

*Round 2 looked up the scanner's account in AD; round 3 wrote the answer. Each
section says where its facts came from: the hand-kept inventory, or AD live.*

![What a human should check next](images/agent-25-stage2-next-steps.png)

*It said plainly what it could not see, and handed the rest to a human.*

**What it got right:** it named the scanner, its account and its job; it kept
"inventory says" apart from "AD says"; it knew AD's last-logon value can be two
weeks stale and refused to read too much into it.

**What it could not do, and why that is the tool's fault, not Claude's:**

- **The 50 example slots all went to one rule.** Results are sorted by level, so
  50 copies of the hourly level-12 rule 92058 filled every slot. That was
  roughly 30,000 of the 39,000 input tokens, and it left nothing for the logon
  events that would answer the question.
- **The search cannot filter by IP address.** "What did 192.168.20.3 do?" needs
  exactly that.
- **The scanner's own logons are not alerts at all.** The lab's tuning rule
  100020 silences `svc-greenbone` logons from SCAN01 (level 0), so they never
  reach the alerts index, only the raw archive, which the agent is denied by
  design. Quieter alerts for humans mean less evidence for the agent: a
  trade-off worth knowing about.

![First attempt: the tunnel was closed](images/agent-22-stage2-tunnel-closed.png)

*The first attempt, with the SSH tunnel closed. The Wazuh search failed, but
the lookups still worked: they go to DC01 directly, not through the tunnel.*

## What I learned

- **An agent is three parts: a model, a loop, and tools.** The model never runs
  anything. It asks; my code decides whether to run it.
- **The agent only knows what its tools return.** Proven by the deletion test.
- **Data minimisation has a visible cost.** Withholding program names kept data
  in the lab but left the agent unable to explain alerts. The fix was not to send
  everything, but to send paths and filter the free text.
- **An agent is only as good as its context.** It could not tell that an IP
  address was the lab's own scanner. That gap is why stage 2 adds an identity
  and asset lookup.
- **Agents over-claim.** Early runs offered to search other machines, which the
  script cannot do. Check what an agent says it can do against the code.
- **Agents can catch your bugs.** It noticed its per-rule counts summed to 724
  while the total was 725. The summary listed only the top 20 rules; the 21st had
  fallen off. Now up to 100 are listed, and any remainder is reported as a count
  instead of disappearing.
- **In AD, "read-only" is the default, not something you grant.** A brand-new
  account with no groups can already read who is in Domain Admins. That is what
  attackers map first, so the agent's tool, not AD, decides what it reads.
- **AD does not know half the lab.** Only Windows machines that joined the
  domain have an AD record, and AD stores no IP addresses. Identity context and
  asset context are two different sources.
- **A certificate is issued to a name.** The agent must dial
  `DC01.corp.biirabank.com`, not `192.168.50.2`, or the name check fails: the
  same lesson as `127.0.0.1` for Wazuh.

## What broke

![Running the script from the wrong folder](images/agent-02-wrong-folder.png)

*First attempts: stray characters pasted before a command, then the script run
from one folder too high.*

- A direct connection to the indexer was refused. Not a network problem: it is
  bound to localhost, which led to the tunnel.
- The certificate file was not where the docs usually say. Reading
  `opensearch.yml` gave the real path. Ask the configuration, do not guess.
- Windows curl refused the indexer with `the revocation status is unknown`.
  Wazuh's homemade CA publishes no revocation list. `--ssl-no-revoke` skips only
  that check. The design debt it exposes: a stolen indexer certificate could not
  be revoked, only replaced by re-issuing from a new CA.
- Python 3.13+ refused the same CA for lacking a "key usage" label. The code
  relaxes only that rule; the chain and the address are still checked.
- The first display test crashed on Windows' old text encoding, which cannot
  print `✓`. The display now forces UTF-8.
- My laptop could not find `DC01.corp.biirabank.com`: "DNS name does not exist".
  It asks public DNS, and the domain's internal names are published only on
  DC01. A one-line `hosts` entry fixes it for this laptop; the lasting fix is
  Tailscale split DNS, which sends only `corp.biirabank.com` questions to DC01.

## Stages

| Stage | What | Status |
|---|---|---|
| 0 | Virtual environment, `anthropic` and `python-dotenv`, key in `.env` | Done 2026-10-13 |
| 1a | The loop by hand, with a fake Wazuh tool returning three made-up alerts | Done 2026-10-13 |
| 1b | A real, read-only Wazuh search with its own identity and verified TLS | Done 2026-10-15 |
| 1c | A web face on the same loop, local only, token-gated | Done 2026-10-16 |
| 2 | Read-only machine and account lookups: lab inventory plus Active Directory over LDAPS, as the agent's own AD account | Built 2026-10-29 |
| 3 | The same agent on the Anthropic SDK's Tool Runner | Not started |

## Run it yourself

Once, in Git Bash inside this folder:

```bash
python -m venv .venv
source .venv/Scripts/activate
pip install -r requirements.txt
```

Then, every time:

1. Open the tunnel in a second window and leave it open:
   `ssh -N -o ServerAliveInterval=30 -L 9200:127.0.0.1:9200 <user>@<siem-host>`
2. Ask from the terminal, or open the web page:

```bash
python agent.py "Is anything unusual happening on WKS01 in the last 24 hours?"
python web.py
```

Files it needs that are never committed:

- `.env` beside `agent.py`: `ANTHROPIC_API_KEY`, `WAZUH_INDEXER_USER`, `WAZUH_INDEXER_PASSWORD` (single-quoted), `AD_BIND_USER` (as `name@domain`), `AD_BIND_PASSWORD`
- `certs/wazuh-root-ca.pem`: Wazuh's public CA certificate from `/etc/wazuh-indexer/certs/root-ca.pem` on the SIEM. The `.pem`, never the `.key`.
- `certs/biira-root-ca.pem`: the lab root CA's public certificate (CA01), which DC01's LDAPS certificate chains to.

The laptop must also resolve `DC01.corp.biirabank.com` (a `hosts` entry, or
split DNS). Check the AD side alone with `python ldap_check.py`.

| File | What it does |
|---|---|
| `agent.py` | The agent: the brief, the tool menu, the loop |
| `directory.py` | `lookup_host` and `lookup_account`: the inventory and AD over LDAPS, allow-listed attributes only |
| `assets.json` | The lab inventory: every machine, its network and its role |
| `ldap_check.py` | Proves the AD sign-in over LDAPS and shows one lookup, with no AI involved |
| `redact.py` / `test_redact.py` | The secret filter for command lines and AD descriptions, and its 18 tests (`python test_redact.py`) |
| `web.py` + `static/` | The web page, on the same loop |
| `display.py` | How the terminal version looks. Changes nothing about how the agent thinks |
| `images/build_animations.py` | Regenerates the animated diagrams from the static ones |
