// Ask my SIEM: the browser face of agent.run_agent().
// Every value that came from Wazuh or Claude is inserted as text, never as HTML,
// except the answer, which goes through md() below: it escapes everything first,
// then adds a small, fixed set of formatting. Alert fields can hold attacker-chosen
// text, and that text must never become live markup on this page.

"use strict";

const TOKEN = new URLSearchParams(location.search).get("token") || "";
const $ = (sel) => document.querySelector(sel);
const CALM = matchMedia("(prefers-reduced-motion: reduce)").matches;

const timeline = $("#timeline");
const input = $("#q");
const go = $("#go");
const avatar = $("#avatar");

let source = null;
let pending = null;   // the card currently showing a spinner
let started = 0;
let ticker = 0;

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
  if (live) {   // shimmering placeholder lines while we wait
    const skel = el("div", "skel");
    skel.append(el("i"), el("i"), el("i"));
    c.append(skel);
    c.dataset.t0 = performance.now();
    pending = c;
  }
  timeline.append(c);
  c.scrollIntoView({ behavior: CALM ? "auto" : "smooth", block: "nearest" });
  return c;
}

function settle(c, title) {
  if (!c) return;
  c.classList.remove("live");
  c.querySelector(".skel")?.remove();
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

function countUp(node, to) {
  if (CALM) { node.textContent = to.toLocaleString(); return; }
  const t0 = performance.now();
  const step = (now) => {
    const p = Math.min(1, (now - t0) / 900);
    node.textContent = Math.round(to * (1 - Math.pow(1 - p, 3))).toLocaleString();
    if (p < 1) requestAnimationFrame(step);
  };
  requestAnimationFrame(step);
}

// ---------- the agent's live panel ----------
// Stations, top to bottom: 0 Claude · 1 agent.py · 2 SSH tunnel · 3 Wazuh
const panel = {
  rail: $("#rail"),
  pipe: $("#pipe"),
  stations: [...document.querySelectorAll("#pipe .st")],
  packet: $("#packet"),
  carry: $("#carry"),
  kicker: $("#kicker"),
  title: $("#state-title"),
  text: $("#state-text"),
  at: 1,
  queue: Promise.resolve(),

  y(i) {
    const p = this.pipe.getBoundingClientRect();
    const o = this.stations[i].querySelector(".orb").getBoundingClientRect();
    return o.top - p.top + o.height / 2;
  },
  mark(i, state) {
    this.stations.forEach((s) => s.classList.remove("active", "busy", "done", "fail"));
    if (i !== null) this.stations[i].classList.add(state);
  },
  // The logo, the headline and the sentence under it all change together.
  state(mood, kicker, title, text) {
    avatar.dataset.state = mood;
    this.rail.dataset.state = mood;
    for (const [node, value] of [[this.kicker, kicker], [this.title, title], [this.text, text]]) {
      if (node.textContent === value) continue;
      node.textContent = value;
      node.classList.remove("swap");
      void node.offsetWidth;   // restart the fade-in
      node.classList.add("swap");
    }
  },
  reset() {
    this.queue = Promise.resolve();
    this.at = 1;
    this.packet.className = "packet on";
    this.packet.style.top = `${this.y(1)}px`;
    this.carry.textContent = "your question";
    this.mark(1, "active");
  },
  // Queue a trip through a list of stations. Trips run one after another, so the
  // panel always shows the order things really happened in.
  travel(path, kind, carrying, after) {
    this.queue = this.queue.then(() => new Promise((done) => {
      this.packet.className = `packet on ${kind}`;
      this.carry.textContent = carrying;
      const frames = [this.at, ...path].map((i) => ({ top: `${this.y(i)}px` }));
      const finish = () => {
        this.at = path[path.length - 1];
        this.packet.style.top = `${this.y(this.at)}px`;
        if (after) after();
        done();
      };
      // Browsers pause animations in background tabs; never let the panel fall
      // behind the real run. Skip the trip, or cut it short if it stalls.
      if (CALM || document.hidden) return finish();
      const duration = 480 * path.length;
      const trip = this.packet.animate(frames, { duration, easing: "cubic-bezier(.45,.05,.3,1)", fill: "forwards" });
      let ended = false;
      const end = () => { if (!ended) { ended = true; trip.cancel(); finish(); } };
      trip.onfinish = end;
      setTimeout(end, duration + 400);
    }));
  },
  then(fn) { this.queue = this.queue.then(fn); },
};

// Move the logo from the hero into the panel, with a smooth glide (FLIP).
function moveAvatarToPanel() {
  const slot = $("#rail-slot");
  if (slot.contains(avatar)) return;
  const from = avatar.getBoundingClientRect();
  slot.append(avatar);
  if (CALM) return;
  const to = avatar.getBoundingClientRect();
  const dx = from.left - to.left;
  const dy = from.top - to.top;
  const s = from.width / to.width;
  avatar.animate(
    [{ transform: `translate(${dx}px, ${dy}px) scale(${s})`, transformOrigin: "top left" },
     { transform: "none", transformOrigin: "top left" }],
    { duration: 750, easing: "cubic-bezier(.2,.8,.2,1)" },
  );
}

function startClock() {
  clearInterval(ticker);
  ticker = setInterval(() => {
    $("#m-time").textContent = `${((performance.now() - started) / 1000).toFixed(1)}s`;
  }, 100);
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
    [r.total_matched, `alerts in ${r.hours}h`, true],
    [r.summary_by_rule.length, "rules", false],
    [r.alerts_shown, "examples sent", false],
    [ev.characters, "characters to Claude", false],
  ]) {
    const s = el("div", `stat${hl ? " hl" : ""}`);
    const num = el("b", "", "0");
    s.append(num, el("span", "", label));
    stats.append(s);
    countUp(num, value);
  }
  c.append(stats);

  const rows = [...r.summary_by_rule].sort((a, b) => b.level - a.level || b.count - a.count);
  const max = Math.max(1, ...rows.map((x) => x.count));
  const rules = el("div", "rules");
  const bars = [];
  for (const [n, row] of rows.entries()) {
    const line = el("div", "rule");
    line.style.animationDelay = `${n * 45}ms`;
    const cls = levelClass(row.level);
    line.append(el("span", `lvl ${cls}`, String(row.level)));
    line.append(el("span", "rid", row.rule_id));
    const d = el("span", "desc", row.description);
    d.title = row.description;
    line.append(d);
    const bar = el("span", "bar");
    const fill = el("i", cls);
    fill.style.transitionDelay = `${150 + n * 45}ms`;
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
    const n = r.alerts.length;
    det.append(el("summary", "", `Show the ${n} alert${n === 1 ? "" : "s"} Claude received`));
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
  [...body.children].forEach((part, n) => {   // reveal it block by block
    part.classList.add("reveal");
    part.style.animationDelay = `${n * 90}ms`;
  });
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
      if (ev.round === 1) {
        panel.travel([0], "", "question + menu of tools", () => {
          panel.mark(0, "busy");
          panel.state("thinking", "Round 1", "Claude is thinking", "Reading your question, its brief and the menu of tools.");
        });
      } else {
        panel.travel([0], "data", "the alerts, nothing else", () => {
          panel.mark(0, "busy");
          panel.state("writing", `Round ${ev.round}`, "Claude is writing", "It sees only what the tool returned. Never the lab itself.");
        });
      }
      break;
    case "round":
      settle(pending, `Round ${ev.round} · ${MEANING[ev.stop_reason] || ev.stop_reason}`);
      $("#m-rounds").textContent = ev.round;
      break;
    case "tool_call": {
      drawToolCall(ev);
      const blanks = Object.values(ev.input).join(", ");
      panel.travel([1], "order", `order: ${blanks}`, () => {
        panel.mark(1, "active");
        panel.state("searching", "Tool call", "Running the search", "agent.py fills the fixed query with Claude's two blanks.");
      });
      panel.travel([2, 3], "", "search, as svc-ask-siem", () => {
        panel.mark(3, "busy");
        panel.state("searching", "Inside the lab", "Searching Wazuh", "Certificate checked, logged in as svc-ask-siem, alerts only.");
      });
      break;
    }
    case "tool_result":
      drawWazuh(ev);
      if (ev.is_error) {
        panel.then(() => {
          panel.mark(2, "fail");
          panel.packet.className = "packet on error";
          panel.carry.textContent = "an error";
          panel.state("error", "Tool error", "Wazuh unreachable", "Is the SSH tunnel open? The error goes back to Claude as it is.");
        });
      } else {
        const n = ev.result.total_matched;
        panel.travel([2, 1], "data", `${n.toLocaleString()} alerts, 12 fields each`, () => {
          panel.mark(1, "active");
          panel.state("searching", "Evidence in", `${n.toLocaleString()} alerts found`, "Only the chosen fields come back. The raw logs stay in the lab.");
          countUp($("#m-alerts"), n);
        });
      }
      break;
    case "answer":
      drawAnswer(ev);
      panel.travel([1], "answer", "the answer", () => {
        panel.mark(1, "done");
        panel.packet.classList.remove("on");
        panel.state("done", "Done", "Answer ready", "Facts from Wazuh, words from Claude. Read it like a junior analyst's report.");
        countUp($("#m-tokens"), ev.tokens_in + ev.tokens_out);
      });
      break;
    case "refusal":
      card("error", "!", "Declined by a safety check", `Category: ${ev.category}`);
      panel.then(() => { panel.mark(0, "fail"); panel.state("error", "Stopped", "Declined", "A safety check declined this request."); });
      break;
    case "gave_up":
      card("error", "!", `Stopped after ${ev.max_rounds} rounds without a final answer`);
      panel.then(() => { panel.mark(1, "fail"); panel.state("error", "Stopped", "No final answer", `Gave up after ${ev.max_rounds} rounds.`); });
      break;
    case "error":
      settle(pending);
      card("error", "!", "Something failed", ev.message);
      panel.then(() => { panel.mark(1, "fail"); panel.state("error", "Error", "Something failed", "The details are in the last card."); });
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
  clearInterval(ticker);
  $("#m-time").textContent = `${((performance.now() - started) / 1000).toFixed(1)}s`;
  go.disabled = false;
  go.textContent = "Ask";
}

function ask(question) {
  question = question.trim();
  if (question.length < 3 || source) return;
  input.value = question;

  document.body.classList.replace("idle", "running");
  panel.rail.hidden = false;
  moveAvatarToPanel();
  timeline.replaceChildren();
  timeline.hidden = false;
  go.disabled = true;
  go.textContent = "Working";
  started = performance.now();
  startClock();
  for (const id of ["#m-rounds"]) $(id).textContent = "0";
  for (const id of ["#m-alerts", "#m-tokens"]) $(id).textContent = "–";

  panel.reset();
  panel.state("thinking", "Starting", "Question received", "agent.py is packing your question with the brief and the menu.");
  card("you", "?", "You asked", question);

  const url = `/ask?q=${encodeURIComponent(question)}&token=${encodeURIComponent(TOKEN)}`;
  source = new EventSource(url);
  source.onmessage = (e) => handle(JSON.parse(e.data));
  source.onerror = () => {
    if (!source) return;
    card("error", "!", "Lost the connection to web.py", "Is it still running in your terminal?");
    panel.state("error", "Error", "Connection lost", "web.py stopped answering.");
    finish();
  };
}

$("#form").addEventListener("submit", (e) => { e.preventDefault(); ask(input.value || input.placeholder); });
$("#chips").addEventListener("click", (e) => {
  if (e.target.tagName === "BUTTON") ask(e.target.textContent);
});
addEventListener("resize", () => { if (!panel.rail.hidden) panel.packet.style.top = `${panel.y(panel.at)}px`; });

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
setInterval(checkTunnel, 8000);
