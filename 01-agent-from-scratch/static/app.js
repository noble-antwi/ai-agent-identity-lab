// Ask my SIEM: the browser face of agent.run_agent().
// Every value that came from Wazuh or Claude is inserted as text, never as HTML,
// except the answer, which goes through md() below: it escapes everything first,
// then adds a small, fixed set of formatting. Alert fields can hold attacker-chosen
// text, and that text must never become live markup on this page.

"use strict";

const TOKEN = new URLSearchParams(location.search).get("token") || "";
const $ = (sel) => document.querySelector(sel);
const timeline = $("#timeline");
const input = $("#q");
const go = $("#go");

let source = null;
let pending = null;   // the card currently showing a spinner
let started = 0;
let clock = 0;

// ---------- small DOM helpers ----------
function el(tag, cls, text) {
  const node = document.createElement(tag);
  if (cls) node.className = cls;
  if (text !== undefined) node.textContent = text;
  return node;
}

function card(kind, icon, title, sub, live) {
  const c = el("article", `card ${kind}${live ? " live" : ""}`);
  c.append(el("div", "icon", icon));
  const head = el("div", "head");
  const t = el("div", "title", title);
  if (live) t.classList.add("dots");
  head.append(t, el("span", "time", ""));
  c.append(head);
  if (sub) c.append(el("div", "sub", sub));
  timeline.append(c);
  c.scrollIntoView({ behavior: "smooth", block: "end" });
  if (live) {
    c.dataset.t0 = performance.now();
    pending = c;
  }
  return c;
}

function settle(c, title) {
  if (!c) return;
  c.classList.remove("live");
  const t = c.querySelector(".title");
  t.classList.remove("dots");
  if (title) t.textContent = title;
  const secs = (performance.now() - Number(c.dataset.t0 || performance.now())) / 1000;
  c.querySelector(".time").textContent = `${secs.toFixed(1)}s`;
  if (pending === c) pending = null;
}

function levelClass(level) {
  if (level >= 12) return "l-high";
  if (level >= 7) return "l-mid";
  if (level >= 4) return "l-low";
  return "";
}

// ---------- tiny, safe markdown ----------
function escapeHtml(s) {
  return s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

function inline(s) {
  return s
    .replace(/`([^`]+)`/g, "<code>$1</code>")
    .replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>")
    .replace(/(^|[^*])\*([^*\s][^*]*)\*/g, "$1<em>$2</em>");
}

function md(src) {
  const out = [];
  let list = null;      // "ul" | "ol" | null
  let sub = false;      // inside a nested <ul>
  let para = [];

  const flushPara = () => { if (para.length) { out.push(`<p>${inline(para.join(" "))}</p>`); para = []; } };
  const closeSub = () => { if (sub) { out.push("</ul></li>"); sub = false; } };
  const closeList = () => {
    if (!list) return;
    if (sub) { out.push("</ul></li>"); sub = false; } else { out.push("</li>"); }
    out.push(`</${list}>`);
    list = null;
  };

  for (const raw of escapeHtml(src).split(/\r?\n/)) {
    const line = raw.replace(/\s+$/, "");
    const indent = line.length - line.trimStart().length;
    const text = line.trim();
    let m;

    if (!text) { flushPara(); continue; }

    if ((m = text.match(/^#{1,4}\s+(.*)$/))) {
      flushPara(); closeList();
      out.push(`<h3>${inline(m[1])}</h3>`);
    } else if ((m = text.match(/^(?:[-*•])\s+(.*)$/)) && list && indent >= 2) {
      if (!sub) { out.push("<ul>"); sub = true; }
      out.push(`<li>${inline(m[1])}</li>`);
    } else if ((m = text.match(/^(\d+)[.)]\s+(.*)$/)) || (m = text.match(/^()(?:[-*•])\s+(.*)$/))) {
      flushPara();
      const kind = m[1] ? "ol" : "ul";
      if (list !== kind) { closeList(); out.push(`<${kind}>`); list = kind; }
      else { closeSub(); out.push("</li>"); }
      out.push(`<li>${inline(m[2])}`);
    } else if ((m = text.match(/^&gt;\s?(.*)$/))) {
      flushPara(); closeList();
      out.push(`<blockquote>${inline(m[1])}</blockquote>`);
    } else if (list && indent >= 2) {
      out.push(` ${inline(text)}`);   // continuation of a list item
    } else {
      closeList();
      para.push(text);
    }
  }
  flushPara(); closeList();
  return out.join("");
}

// ---------- drawing each event ----------
const MEANING = {
  tool_use: "Claude ordered from the menu",
  end_turn: "Claude wrote the answer",
  max_tokens: "Claude ran out of room",
  refusal: "A safety check declined",
};

function drawToolCall(ev) {
  const c = card("tool", "⚙", "Claude ordered from the menu",
    "It only fills in the blanks. The query itself is fixed in agent.py.");
  const call = el("div", "call");
  call.append(el("span", "fn", ev.name));
  for (const [k, v] of Object.entries(ev.input)) {
    const b = el("span", "blank");
    b.append(el("span", "", `${k} `), document.createTextNode(String(v)));
    call.append(b);
  }
  c.append(call);
  card("wazuh", "W", "Searching Wazuh through the SSH tunnel, as svc-ask-siem", "", true);
}

function drawWazuh(ev) {
  const c = pending;
  if (ev.is_error) {
    settle(c, "Wazuh could not be searched");
    c.classList.replace("wazuh", "error");
    c.append(el("div", "sub", ev.output));
    return;
  }
  const r = ev.result;
  settle(c, `Wazuh answered: ${r.total_matched.toLocaleString()} alerts on ${r.agent_name}`);

  const stats = el("div", "stats");
  for (const [value, label, hl] of [
    [r.total_matched.toLocaleString(), `alerts in ${r.hours}h`, true],
    [r.summary_by_rule.length, "rules", false],
    [r.alerts_shown, "examples sent", false],
    [ev.characters.toLocaleString(), "characters to Claude", false],
  ]) {
    const s = el("div", `stat${hl ? " hl" : ""}`);
    s.append(el("b", "", String(value)), el("span", "", label));
    stats.append(s);
  }
  c.append(stats);

  const rows = [...r.summary_by_rule].sort((a, b) => b.level - a.level || b.count - a.count);
  const max = Math.max(1, ...rows.map((x) => x.count));
  const rules = el("div", "rules");
  const bars = [];
  for (const row of rows) {
    const line = el("div", "rule");
    const cls = levelClass(row.level);
    line.append(el("span", `lvl ${cls}`, String(row.level)));
    line.append(el("span", "rid", row.rule_id));
    const d = el("span", "desc", row.description);
    d.title = row.description;
    line.append(d);
    const bar = el("span", "bar");
    const fill = el("i", cls);
    bar.append(fill);
    bars.push([fill, Math.max(2, (row.count / max) * 100)]);
    line.append(bar);
    line.append(el("span", "cnt", row.count.toLocaleString()));
    rules.append(line);
  }
  c.append(rules);
  requestAnimationFrame(() => requestAnimationFrame(() => bars.forEach(([f, w]) => { f.style.width = `${w}%`; })));

  if (r.alerts.length) {
    const det = el("details", "examples");
    det.append(el("summary", "", `Show the ${r.alerts.length} alerts Claude received`));
    const wrap = el("div", "wrap");
    const table = el("table");
    const cols = [["timestamp", "Time"], ["rule.level", "Lvl"], ["rule.id", "Rule"], ["rule.description", "Description"],
                  ["data.win.eventdata.targetUserName", "Account"], ["data.win.eventdata.ipAddress", "Source IP"]];
    const thead = el("tr");
    cols.forEach(([, h]) => thead.append(el("th", "", h)));
    table.append(thead);
    for (const a of r.alerts) {
      const tr = el("tr");
      cols.forEach(([k]) => tr.append(el("td", "", a[k] === undefined ? "" : String(a[k]).replace("T", " ").slice(0, k === "timestamp" ? 19 : 200))));
      table.append(tr);
    }
    wrap.append(table);
    det.append(wrap);
    c.append(det);
  }
}

function drawAnswer(ev) {
  const c = card("answer", "✓", "The answer", "Every claim should cite a rule id and a time. Check it like you would a junior analyst's report.");
  const body = el("div", "md");
  body.innerHTML = md(ev.text);   // safe: md() escapes before formatting
  c.append(body);
  const meta = el("div", "meta");
  const secs = ((performance.now() - started) / 1000).toFixed(1);
  for (const m of [`${ev.rounds} rounds`, `${ev.tokens_in.toLocaleString()} tokens in`,
                   `${ev.tokens_out.toLocaleString()} tokens out`, `${secs}s`]) {
    meta.append(el("span", "", m));
  }
  c.append(meta);
}

function handle(ev) {
  switch (ev.type) {
    case "thinking":
      card("think", "✦", `Round ${ev.round} · Claude is thinking`,
        ev.round === 1 ? "Reading your question, its brief and the menu of tools" : "Reading what the tool brought back", true);
      break;
    case "round":
      settle(pending, `Round ${ev.round} · ${MEANING[ev.stop_reason] || ev.stop_reason}`);
      break;
    case "tool_call":
      drawToolCall(ev);
      break;
    case "tool_result":
      drawWazuh(ev);
      break;
    case "answer":
      drawAnswer(ev);
      break;
    case "refusal":
      card("error", "!", "Declined by a safety check", `Category: ${ev.category}`);
      break;
    case "gave_up":
      card("error", "!", `Stopped after ${ev.max_rounds} rounds without a final answer`);
      break;
    case "error":
      settle(pending);
      card("error", "!", "Something failed", ev.message);
      break;
    case "done":
      finish();
      break;
  }
}

// ---------- running a question ----------
function finish() {
  if (source) { source.close(); source = null; }   // stop the browser from auto-reconnecting
  settle(pending);
  go.disabled = false;
  go.textContent = "Ask";
}

function ask(question) {
  question = question.trim();
  if (question.length < 3 || source) return;
  timeline.replaceChildren();
  timeline.hidden = false;
  go.disabled = true;
  go.textContent = "Working";
  started = performance.now();
  card("you", "?", "You asked", question);

  const url = `/ask?q=${encodeURIComponent(question)}&token=${encodeURIComponent(TOKEN)}`;
  source = new EventSource(url);
  source.onmessage = (e) => handle(JSON.parse(e.data));
  source.onerror = () => {
    if (!source) return;
    card("error", "!", "Lost the connection to web.py", "Is it still running in your terminal?");
    finish();
  };
}

$("#form").addEventListener("submit", (e) => { e.preventDefault(); ask(input.value || input.placeholder); });
$("#chips").addEventListener("click", (e) => {
  if (e.target.tagName === "BUTTON") { input.value = e.target.textContent; ask(input.value); }
});

// ---------- tunnel status ----------
async function checkTunnel() {
  const pill = $("#tunnel");
  try {
    const res = await fetch(`/health?token=${encodeURIComponent(TOKEN)}`);
    if (!res.ok) throw new Error(res.status);
    const h = await res.json();
    pill.className = `pill status ${h.tunnel ? "up" : "down"}`;
    pill.querySelector("span").textContent = h.tunnel ? "tunnel open" : "tunnel closed";
  } catch {
    pill.className = "pill status down";
    pill.querySelector("span").textContent = "web.py not reachable";
  }
}
checkTunnel();
clock = setInterval(checkTunnel, 8000);
