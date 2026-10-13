// KinVault desktop UI. Talks to kinvaultd through the app's Rust commands;
// all text from the daemon or from friends is inserted as text, never HTML.
"use strict";

const { invoke } = window.__TAURI__.core;
/// Served by `kinvaultd --web` (see web.js) rather than the desktop app.
const WEB = !!window.KINVAULT_WEB;
const { listen } = window.__TAURI__.event;

const GiB = 1024 ** 3;
const MiB = 1024 ** 2;

const state = {
  page: "backups",
  connected: false,
  status: null, // DaemonStatus
  peers: [],
  invites: [],
  network: null, // NetworkInfo
  nearby: { until_unix: null, devices: [] }, // NearbyStatus
  progress: {}, // set id -> latest Progress event
  autostart: false,
  restoreSet: null,
  snapshotsSet: null, // the set whose versions are in `snapshots`
  snapshots: [],
  snapshotsError: null, // why the restore set's versions couldn't be loaded
  snapshotsLoading: false,
  selectedSnapshot: null,
};

// ---------- small helpers ----------

function el(tag, attrs, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === false || v === null || v === undefined) continue;
    if (k === "class") node.className = v;
    else if (k.startsWith("on")) node.addEventListener(k.slice(2), v);
    else if (v === true) node.setAttribute(k, "");
    else node.setAttribute(k, v);
  }
  for (const c of children.flat()) {
    if (c === null || c === undefined || c === false) continue;
    node.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return node;
}

function bytes(n) {
  if (n === null || n === undefined) return "unlimited";
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let v = n, u = 0;
  while (v >= 1024 && u < units.length - 1) { v /= 1024; u++; }
  return u === 0 ? `${n} B` : `${v.toFixed(v < 10 ? 1 : 0)} ${units[u]}`;
}

function plural(n, word) {
  return `${n} ${word}${n === 1 ? "" : "s"}`;
}

function ago(unixSeconds) {
  const s = Math.max(0, Date.now() / 1000 - unixSeconds);
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
  return `${Math.floor(s / 86400)} days ago`;
}

function dateTime(unixSeconds) {
  return new Date(unixSeconds * 1000).toLocaleString();
}

function date(unixSeconds) {
  return new Date(unixSeconds * 1000).toLocaleDateString();
}

function toast(message, bad = false) {
  const t = el("div", { class: bad ? "toast bad" : "toast" }, message);
  document.getElementById("toasts").append(t);
  setTimeout(() => t.remove(), bad ? 8000 : 4500);
}

function shortId(id) {
  return id.length > 16 ? `${id.slice(0, 8)}…${id.slice(-6)}` : id;
}

/// Sends a request to kinvaultd and unwraps the reply's payload.
async function call(method, params) {
  const request = params === undefined ? { method } : { method, params };
  const reply = await invoke("daemon_call", { request });
  if (typeof reply === "string") return reply; // e.g. "Done"
  return Object.values(reply)[0];
}

/// Runs an action, showing a toast on failure. Returns the result or undefined.
async function attempt(fn, button) {
  if (button) button.disabled = true;
  try {
    return await fn();
  } catch (e) {
    toast(String(e), true);
  } finally {
    if (button) button.disabled = false;
  }
}

function peerName(id) {
  const p = state.peers.find((p) => p.id === id);
  return p?.name || shortId(id);
}

function describeTarget(target) {
  return target.kind === "local" ? `Folder ${target.path}` : `${peerName(target.id)}`;
}

function describeGrant(g) {
  const parts = [g.quota_bytes ? `${bytes(g.quota_bytes)} storage` : "unlimited storage"];
  if (g.upload_limit) parts.push(`max ${bytes(g.upload_limit)}/s`);
  if (g.window) parts.push(`uploads ${g.window}`);
  return parts.join(", ");
}

/** " (12 MiB marked for deletion)" when part of what a peer stores here is waiting to be erased. */
function deletingNote(peer) {
  return peer.deleting_bytes ? ` (${bytes(peer.deleting_bytes)} marked for deletion)` : "";
}

function notAllowed(peer) {
  return peer.used_bytes
    ? `Not allowed to store backups here · ${bytes(peer.used_bytes)} left here${deletingNote(peer)}`
    : "Not allowed to store backups here";
}

function describePolicy(p) {
  const parts = [["last", "latest"], ["hourly", "hourly"], ["daily", "daily"], ["weekly", "weekly"], ["monthly", "monthly"], ["yearly", "yearly"]]
    .filter(([k]) => p[k] !== null && p[k] !== undefined)
    .map(([k, label]) => `${p[k]} ${label}`);
  return parts.length ? parts.join(", ") : "everything";
}

// ---------- generic modal form ----------

/**
 * Shows a modal form. `fields` describe inputs; resolves with the values, or
 * null if cancelled. `validate(values)` may return an error message.
 */
function form({ title, intro, fields = [], ok = "OK", danger = false, validate, onSubmit }) {
  const dialog = document.getElementById("modal");
  dialog.replaceChildren();
  const inputs = {};
  const body = el("div", { class: "modal-body" }, el("h3", {}, title), intro ? el("p", { class: "muted" }, intro) : null);

  for (const f of fields) {
    if (f.type === "custom") {
      body.append(f.node);
      continue;
    }
    if (f.type === "pair") {
      const wrap = el("div", { class: "pair" });
      for (const sub of f.fields) wrap.append(fieldNode(sub, inputs));
      body.append(wrap);
      continue;
    }
    body.append(fieldNode(f, inputs));
  }
  const error = el("div", { class: "form-error", hidden: true });
  body.append(error);

  return new Promise((resolve) => {
    const values = () => Object.fromEntries(Object.entries(inputs).map(([k, get]) => [k, get()]));
    const cancel = el("button", { class: "btn", type: "button", onclick: () => { dialog.close(); resolve(null); } }, "Cancel");
    const submit = el("button", { class: danger ? "btn danger" : "btn primary", type: "button" }, ok);
    submit.addEventListener("click", async () => {
      const v = values();
      const problem = validate?.(v);
      if (problem) {
        error.textContent = problem;
        error.hidden = false;
        return;
      }
      if (onSubmit) {
        submit.disabled = true;
        try {
          const result = await onSubmit(v);
          if (result === false) return; // keep open
        } catch (e) {
          error.textContent = String(e);
          error.hidden = false;
          return;
        } finally {
          submit.disabled = false;
        }
      }
      dialog.close();
      resolve(v);
    });
    dialog.append(body, el("div", { class: "modal-foot" }, cancel, submit));
    dialog.onclose = () => resolve(null);
    dialog.showModal();
    body.querySelector("input, textarea, select")?.focus();
  });
}

function fieldNode(f, inputs) {
  const id = `f-${f.name}`;
  let input;
  let get;
  switch (f.type) {
    case "checkbox":
      input = el("input", { type: "checkbox", id, checked: !!f.value });
      inputs[f.name] = () => input.checked;
      return el("div", { class: "field check" }, el("label", { for: id }, input, f.label), f.hint ? el("div", { class: "hint" }, f.hint) : null);
    case "select":
      input = el("select", { id }, f.options.map(([value, label]) => el("option", { value, selected: value === f.value }, label)));
      if (f.onchange) input.addEventListener("change", () => f.onchange(input.value));
      get = () => input.value;
      break;
    case "textarea":
      input = el("textarea", { id, placeholder: f.placeholder || "", readonly: f.readonly });
      input.value = f.value || "";
      get = () => input.value.trim();
      break;
    case "folders": {
      const chosen = [...(f.value || [])];
      const box = el("div", { class: "list-box" });
      const draw = () => {
        box.replaceChildren(
          ...(chosen.length ? chosen.map((p, i) =>
            el("div", { class: "item" }, el("span", {}, p),
              el("button", { class: "btn small", type: "button", onclick: () => { chosen.splice(i, 1); draw(); } }, "Remove")))
            : [el("div", { class: "item muted" }, f.empty || "Nothing chosen yet")]));
      };
      draw();
      const add = el("button", { class: "btn small", type: "button" }, f.multiple ? "Add folders…" : "Choose folder…");
      add.addEventListener("click", async () => {
        const picked = await attempt(() => invoke("pick_folders", { multiple: !!f.multiple }));
        if (!picked) return;
        if (!f.multiple) chosen.length = 0;
        for (const p of picked) if (!chosen.includes(p)) chosen.push(p);
        draw();
      });
      inputs[f.name] = () => [...chosen];
      return el("div", { class: "field", id: `wrap-${f.name}`, hidden: f.hidden }, el("label", {}, f.label), box,
        el("div", { class: "row", style: "margin-top:6px" }, add), f.hint ? el("div", { class: "hint" }, f.hint) : null);
    }
    default:
      input = el("input", { id, type: f.type || "text", placeholder: f.placeholder || "", min: f.min, step: f.step, autocomplete: "off" });
      if (f.value !== undefined && f.value !== null) input.value = f.value;
      get = () => input.value.trim();
  }
  inputs[f.name] = get;
  return el("div", { class: "field", id: `wrap-${f.name}`, hidden: f.hidden }, el("label", { for: id }, f.label, f.info ? infoTip(f.info) : null), input,
    f.hint ? el("div", { class: "hint" }, f.hint) : null);
}

function show(name, visible) {
  const node = document.getElementById(`wrap-${name}`);
  if (node) node.hidden = !visible;
}

function confirmDialog(title, intro, ok, danger = true) {
  return form({ title, intro, ok, danger }).then((v) => v !== null);
}

/** Optional number field (in `unit` multiples) → bytes or null. */
function toBytes(value, unit) {
  if (value === "" || value === undefined) return null;
  const n = Number(value);
  return Number.isFinite(n) && n > 0 ? Math.round(n * unit) : null;
}

function windowFrom(start, end) {
  return start && end ? `${start}-${end}` : null;
}

/** The rules for exclude patterns, shown from the ⓘ next to "Leave out". */
function excludeRules() {
  const code = (t) => el("code", {}, t);
  const examples = [
    ["*.bat", "every .bat file, anywhere"],
    ["/media/*.bat", ".bat files directly in /media"],
    ["/media/.../*.bat", ".bat files in /media and all its subfolders"],
    ["/media/*", "the files in /media, but not its subfolders"],
    ["/media/...", "everything in /media"],
    ["target/...", "every folder named target, with its contents"],
  ];
  return [
    el("strong", {}, "How patterns work"),
    el("ul", {},
      el("li", {}, "One pattern per line."),
      el("li", {}, code("*"), " matches any part of a name and ", code("?"), " one character. Neither crosses a ", code("/"), "."),
      el("li", {}, code("..."), " matches any number of folders, including none."),
      el("li", {}, "Starting with ", code("/"), " means a full path. Otherwise the pattern matches at any depth."),
      el("li", {}, "Ending in ", code("/..."), " or ", code("/"), " leaves out a folder and everything in it. Other patterns only match files.")),
    el("table", {}, el("tbody", {}, examples.map(([p, what]) => el("tr", {}, el("td", {}, code(p)), el("td", {}, what))))),
    el("p", {}, "Changes apply from the next backup. Versions already backed up keep these files until they're cleaned up."),
  ];
}

function excludeField(value = []) {
  return { name: "excludes", label: "Leave out (optional)", type: "textarea", placeholder: "target/...\nnode_modules/\n*.o",
    value: value.join("\n"), hint: "One pattern per line, e.g. target/... or *.o",
    info: { label: "How leave-out patterns work", content: excludeRules } };
}

let infoTips = 0;

/** An ⓘ button showing `content` on hover, focus or click. */
function infoTip({ label, content }) {
  const tip = el("div", { class: "info-tip", role: "tooltip", id: `info-tip-${++infoTips}` }, content());
  const button = el("button", { type: "button", class: "info-btn", "aria-label": label, "aria-describedby": tip.id }, "i");
  const wrap = el("span", { class: "info" }, button, tip);
  // Clicking the tip's text mustn't act on the surrounding <label>.
  tip.addEventListener("click", (e) => e.preventDefault());
  // Fixed to the window, so the dialog's scrolling body can't cut it off:
  // as wide as its field, below the ⓘ, or above it if there isn't room.
  tip.place = () => {
    const field = (wrap.closest(".field") || wrap).getBoundingClientRect();
    const at = button.getBoundingClientRect();
    tip.style.left = `${field.left}px`;
    tip.style.width = `${field.width}px`;
    const height = tip.offsetHeight;
    const below = at.bottom + 6;
    tip.style.top = `${below + height <= window.innerHeight - 8 ? below : Math.max(8, at.top - 6 - height)}px`;
  };
  for (const ev of ["mouseenter", "focusin", "click"]) wrap.addEventListener(ev, () => requestAnimationFrame(tip.place));
  button.addEventListener("click", (e) => {
    e.preventDefault(); // inside a <label>: don't move focus to its input
    wrap.classList.toggle("open");
  });
  button.addEventListener("blur", () => wrap.classList.remove("open"));
  button.addEventListener("keydown", (e) => {
    // Escape closes the tip first, and the dialog only on a second press.
    if (e.key === "Escape" && wrap.matches(".open, :hover, :focus-within")) {
      e.preventDefault();
      e.stopPropagation();
      wrap.classList.remove("open");
      button.blur();
    }
  });
  return wrap;
}

function excludesFrom(text) {
  return text.split("\n").map((l) => l.trim()).filter(Boolean);
}

function grantFields(g = {}) {
  const [ws, we] = (g.window || "-").split("-");
  return [
    { name: "quota", label: "Storage they may use (GB)", type: "number", min: "0", step: "any", placeholder: "Unlimited", value: g.quota_bytes ? (g.quota_bytes / GiB).toFixed(0) : "" },
    { name: "rate", label: "Upload speed limit (MB/s)", type: "number", min: "0", step: "any", placeholder: "No limit", value: g.upload_limit ? (g.upload_limit / MiB).toFixed(1) : "" },
    { type: "pair", fields: [
      { name: "from", label: "Accept uploads from", type: "time", value: ws || "", hint: "Leave empty for any time" },
      { name: "to", label: "until", type: "time", value: we || "" },
    ] },
  ];
}

function grantFrom(v) {
  return { quota_bytes: toBytes(v.quota, GiB), upload_limit: toBytes(v.rate, MiB), window: windowFrom(v.from, v.to) };
}

function windowProblem(v) {
  return (!!v.from) !== (!!v.to) ? "Set both times for the upload window, or neither." : null;
}

// ---------- data ----------

async function refreshStatus() {
  if (!state.connected) return;
  try {
    state.status = await call("status");
  } catch (e) {
    return;
  }
  render();
}

async function refreshPeers() {
  if (!state.connected) return;
  try {
    [state.peers, state.invites] = await Promise.all([call("peer_list"), call("list_invites")]);
  } catch (e) {
    return;
  }
  render();
}

async function refreshNetwork() {
  if (!state.connected) return;
  try {
    state.network = await call("get_network");
  } catch (e) {
    return;
  }
  if (state.page === "settings") render();
}

async function refreshNearby() {
  if (!state.connected) return;
  try {
    state.nearby = await call("nearby_status");
  } catch (e) {
    return;
  }
  if (state.page === "mine") render();
}

let refreshTimer = null;
function refreshSoon() {
  clearTimeout(refreshTimer);
  refreshTimer = setTimeout(refreshStatus, 150);
}

// ---------- pages ----------

function render() {
  renderBanner();
  document.getElementById("conn-dot").className = `dot ${state.connected ? "on" : "off"}`;
  document.getElementById("conn-text").textContent = state.connected
    ? (state.status ? state.status.name : "Connected")
    : "Service not running";
  const renderers = { backups: renderBackups, restore: renderRestore, mine: renderMine, friends: renderFriends, settings: renderSettings };
  for (const name of Object.keys(renderers)) {
    document.getElementById(`page-${name}`).hidden = name !== state.page;
  }
  renderers[state.page]();
  updateRestoreNav();
}

function renderBanner() {
  const banner = document.getElementById("banner");
  if (state.connected) {
    banner.hidden = true;
    return;
  }
  if (WEB) {
    banner.replaceChildren(el("div", { class: "spacer" },
      el("strong", {}, "Lost the connection to the KinVault server. "), "Reconnecting…"));
    banner.hidden = false;
    return;
  }
  const start = el("button", { class: "btn primary" }, "Start it");
  start.addEventListener("click", () => attempt(async () => {
    await invoke("start_daemon");
    toast("Starting the background service…");
  }, start));
  banner.replaceChildren(
    el("div", { class: "spacer" },
      el("strong", {}, "The KinVault background service isn't running. "),
      "Backups only happen while it runs. Turn on “Start at login” in Settings to keep it running."),
    start);
  banner.hidden = false;
}

function stateChip(set) {
  if (set.state === "running") return el("span", { class: "chip run" }, "Backing up");
  if (set.state === "paused") return el("span", { class: "chip warn" }, "Paused");
  if (set.last_error) return el("span", { class: "chip bad" }, "Needs attention");
  if (set.last_verify && !set.last_verify.ok) return el("span", { class: "chip bad" }, "Problems found");
  if (set.state === "changes_pending") return el("span", { class: "chip" }, "Changes waiting");
  if (set.state === "waiting_for_window") return el("span", { class: "chip" }, "Waiting for its hours");
  if (!set.last_backup) return el("span", { class: "chip" }, "Not backed up yet");
  return el("span", { class: "chip ok" }, "Up to date");
}

function renderBackups() {
  const page = document.getElementById("page-backups");
  const add = el("button", { class: "btn primary", disabled: !state.connected, onclick: newSetDialog }, "New backup");
  page.replaceChildren(el("div", { class: "page-head" }, el("h1", {}, "Backups"), add));
  const sets = state.status?.sets || [];
  const stopped = state.status?.stopped_sets || [];
  if (!sets.length) {
    page.append(el("div", { class: "card empty" },
      el("div", {}, state.connected ? "Nothing is being backed up yet." : "Start the background service to see your backups."),
      state.connected ? el("button", { class: "btn primary", onclick: newSetDialog }, "Choose what to back up") : null));
  }
  for (const set of sets) page.append(setCard(set));
  if (stopped.length) {
    page.append(el("h2", {}, "Stopped"),
      el("p", { class: "muted" }, "These no longer back up. You can still restore from them until their backups are erased."));
    for (const set of stopped) page.append(stoppedSetCard(set));
  }
}

function stoppedSetCard(set) {
  return el("div", { class: "card" },
    el("div", { class: "card-head" }, el("span", { class: "card-title" }, set.name), el("span", { class: "chip warn" }, "Stopped"),
      el("span", { class: "spacer" }), el("span", { class: "card-sub" }, `→ ${describeTarget(set.target)}`)),
    el("div", { class: "paths" }, set.paths.join(" · ")),
    el("div", { class: "lines" },
      el("div", {}, `Stopped ${dateTime(set.stopped_unix)}. Its backups are erased on ${date(set.erase_after_unix)}.`)),
    el("div", { class: "actions" },
      el("button", { class: "btn small", onclick: () => { state.restoreSet = set.id; go("restore"); } }, "Restore…"),
      el("button", { class: "btn small danger", onclick: () => deleteSet(set) }, "Delete permanently…")));
}

/** Every set that can be restored from: running ones, then stopped ones. */
function restorableSets() {
  return [...(state.status?.sets || []), ...(state.status?.stopped_sets || [])];
}

function setCard(set) {
  const lines = el("div", { class: "lines" });
  const progress = state.progress[set.id];
  if (set.state === "running") {
    lines.append(el("div", {}, progress
      ? `Scanned ${plural(progress.files, "file")} (${bytes(progress.total_bytes)}), read ${bytes(progress.bytes_read)}, sent ${bytes(progress.bytes_uploaded)}`
      : "Starting…"));
    lines.append(el("div", { class: "progress indeterminate" }, el("div")));
  }
  if (set.last_backup) {
    const b = set.last_backup;
    lines.append(el("div", {},
      `Last backup ${ago(b.time_ns / 1e9)} · ${plural(b.files, "file")}, ${bytes(b.total_bytes)} · ${b.files_changed} changed, sent ${bytes(b.bytes_uploaded)}`));
    if (b.warnings.length) lines.append(el("div", { class: "muted small" }, `${b.warnings.length} item(s) couldn't be read: ${b.warnings.slice(0, 2).join("; ")}`));
  }
  if (set.last_verify) {
    const v = set.last_verify;
    lines.append(el("div", { class: "muted" },
      v.ok ? `Last check ${ago(v.time_unix)}: all good` : `Last check ${ago(v.time_unix)} found problems`));
  }
  const limits = [];
  if (set.upload_limit) limits.push(`max ${bytes(set.upload_limit)}/s`);
  if (set.window) limits.push(`backs up automatically ${set.window}`);
  limits.push(`keeps ${describePolicy(set.retention)}`);
  if (set.excludes?.length) limits.push(`leaves out ${set.excludes.join(", ")}`);
  lines.append(el("div", { class: "muted small" }, limits.join(" · ")));

  const backup = el("button", { class: "btn primary small", disabled: set.state === "running" || set.state === "paused" }, "Back up now");
  backup.addEventListener("click", () => attempt(async () => {
    const b = await call("backup_now", { set: set.id });
    toast(`${set.name}: backed up, ${b.files_changed} changed, sent ${bytes(b.bytes_uploaded)}`);
  }, backup));
  const pause = set.state === "paused"
    ? el("button", { class: "btn small", onclick: () => resumeSet(set) }, "Resume")
    : el("button", { class: "btn small", onclick: () => attempt(() => call("pause_set", { set: set.id })) }, "Pause");
  const check = el("button", { class: "btn small" }, "Check now");
  check.addEventListener("click", () => attempt(async () => {
    const v = await call("verify", { set: set.id, max_bytes: null });
    if (v.ok) toast(`${set.name}: checked ${bytes(v.bytes_checked)}, all good`);
    else toast(`${set.name}: problems found — ${v.errors.slice(0, 2).join("; ")}`, true);
  }, check));
  const prune = el("button", { class: "btn small" }, "Clean up old versions");
  prune.addEventListener("click", () => attempt(async () => {
    const p = await call("prune", { set: set.id });
    toast(`${set.name}: removed ${p.snapshots_removed} old version(s), freed about ${bytes(p.bytes_deleted)}`);
  }, prune));
  const more = el("button", { class: "btn small", onclick: () => setSettingsDialog(set) }, "Settings…");

  return el("div", { class: "card" },
    el("div", { class: "card-head" }, el("span", { class: "card-title" }, set.name), stateChip(set),
      el("span", { class: "spacer" }), el("span", { class: "card-sub" }, `→ ${describeTarget(set.target)}`)),
    el("div", { class: "paths" }, set.paths.join(" · ")),
    lines,
    set.last_error ? el("div", { class: "notice bad" }, set.last_error) : null,
    set.state === "paused" ? el("div", { class: "notice warn" }, "Paused: changes aren't being backed up. Restores still work.") : null,
    el("div", { class: "actions" }, backup,
      el("button", { class: "btn small", onclick: () => { state.restoreSet = set.id; go("restore"); } }, "Restore…"),
      check, prune, pause, more));
}

async function resumeSet(set) {
  try {
    await call("resume_set", { set: set.id, paths: null });
    toast(`${set.name} resumed`);
  } catch (e) {
    // After recovery on a new machine the old paths may not exist.
    const v = await form({
      title: `Resume ${set.name}`,
      intro: `${e} Choose the folders to back up on this machine.`,
      fields: [{ name: "paths", label: "Folders", type: "folders", multiple: true }],
      ok: "Resume",
      validate: (v) => (v.paths.length ? null : "Choose at least one folder."),
      onSubmit: (v) => call("resume_set", { set: set.id, paths: v.paths }),
    });
    if (v) toast(`${set.name} resumed`);
  }
}

async function setSettingsDialog(set) {
  const [ws, we] = (set.window || "-").split("-");
  const r = set.retention;
  const v = await form({
    title: `${set.name} settings`,
    fields: [
      { name: "rate", label: "Upload speed limit (MB/s)", type: "number", min: "0", step: "any", placeholder: "No limit", value: set.upload_limit ? (set.upload_limit / MiB).toFixed(1) : "" },
      { type: "pair", fields: [
        { name: "from", label: "Back up automatically from", type: "time", value: ws || "", hint: "Leave empty for any time" },
        { name: "to", label: "until", type: "time", value: we || "" },
      ] },
      { type: "pair", fields: [
        { name: "last", label: "Keep latest", type: "number", min: "0", value: r.last ?? "" },
        { name: "daily", label: "Keep daily", type: "number", min: "0", value: r.daily ?? "" },
      ] },
      { type: "pair", fields: [
        { name: "weekly", label: "Keep weekly", type: "number", min: "0", value: r.weekly ?? "" },
        { name: "monthly", label: "Keep monthly", type: "number", min: "0", value: r.monthly ?? "" },
      ] },
      excludeField(set.excludes || []),
      { type: "custom", node: el("div", { class: "hint field" }, "Leave all “Keep” boxes empty to keep every version. Hourly/yearly rules: ",
        `${r.hourly ?? "none"} hourly, ${r.yearly ?? "none"} yearly (kept as they are).`) },
      { type: "custom", node: el("div", { class: "field row" },
        el("button", { class: "btn danger small", type: "button", onclick: () => removeSet(set) }, "Stop backing up this set…"),
        el("button", { class: "btn danger small", type: "button", onclick: () => deleteSet(set) }, "Delete permanently…")) },
    ],
    ok: "Save",
    validate: windowProblem,
    onSubmit: async (v) => {
      const num = (x) => (x === "" ? null : Math.max(0, Math.floor(Number(x))));
      // First, so an invalid pattern stops the whole save.
      const excludes = excludesFrom(v.excludes);
      if (excludes.join("\n") !== (set.excludes || []).join("\n")) await call("set_excludes", { set: set.id, excludes });
      await call("set_limits", { set: set.id, upload_limit: toBytes(v.rate, MiB), window: windowFrom(v.from, v.to) });
      await call("set_retention", { set: set.id, policy: { last: num(v.last), hourly: r.hourly, daily: num(v.daily), weekly: num(v.weekly), monthly: num(v.monthly), yearly: r.yearly } });
    },
  });
  if (v) toast("Saved");
}

async function removeSet(set) {
  document.getElementById("modal").close();
  const days = state.status?.keep_deleted_days ?? 30;
  const until = date(Date.now() / 1000 + days * 86400);
  if (!await confirmDialog(`Stop backing up ${set.name}?`,
    `New changes won't be backed up. You can still restore from its backups until ${until}; then they're erased. ` +
    "To keep them longer, change how long deleted data is kept in Settings first.",
    "Stop backing up")) return;
  await attempt(() => call("remove_set", { set: set.id }));
}

const DELETE_CONFIRMATION = "DELETE PERMANENTLY";

async function deleteSet(set) {
  document.getElementById("modal").close();
  const where = set.target.kind === "local" ? `the folder ${set.target.path}` : peerName(set.target.id);
  let result = null;
  const v = await form({
    title: `Delete ${set.name} permanently?`,
    intro: `This deletes ${set.name} and every version of it that was backed up. Its key is erased from this computer now, ` +
      `and ${where} erases the backups in a week. They can't be restored afterwards, not even with a recovery kit.`,
    fields: [{ name: "confirm", label: `Type ${DELETE_CONFIRMATION} to confirm`, placeholder: DELETE_CONFIRMATION }],
    ok: "Delete permanently",
    danger: true,
    validate: (v) => (v.confirm === DELETE_CONFIRMATION ? null : `Type ${DELETE_CONFIRMATION} exactly, in capitals.`),
    onSubmit: async () => { result = await call("delete_set", { set: set.id }); },
  });
  if (!v || !result) return;
  if (result.erase_after_unix && !result.error) {
    toast(`${set.name} deleted. ${set.target.kind === "local" ? "Its backup folder" : where} will erase the backups on ${date(result.erase_after_unix)}.`);
  } else if (result.retrying) {
    toast(`${set.name} deleted. ${where} couldn't be reached, so KinVault will keep asking it to erase the backups.`);
  } else {
    toast(`${set.name} deleted. ${where} didn't erase the backups: ${result.error}`);
  }
}

async function newSetDialog() {
  // Your own devices first, friends last; within each, those that agreed to
  // keep your backups come first.
  const byHosting = (a, b) => !!b.hosts_us - !!a.hosts_us;
  const mine = state.peers.filter((p) => p.mine).sort(byHosting);
  const friends = state.peers.filter((p) => !p.mine).sort(byHosting);
  const space = (p) => (p.hosts_us ? ` (${p.hosts_us.quota_bytes ? bytes(p.hosts_us.quota_bytes) : "unlimited"})` : "");
  const options = [
    ...mine.map((p) => [`peer:${p.id}`, `${p.name || shortId(p.id)}${space(p)}`]),
    ["local", "A folder or external drive…"],
    ["id", "Another KinVault instance (paste its id)…"],
    ...friends.map((p) => [`peer:${p.id}`, `Friend: ${p.name || shortId(p.id)}${space(p)}`]),
  ];
  const v = await form({
    title: "New backup",
    intro: "Files are encrypted on this computer before they leave it. Only you can read them.",
    fields: [
      { name: "name", label: "Name", placeholder: "e.g. Documents" },
      { name: "paths", label: "What to back up", type: "folders", multiple: true },
      excludeField(),
      { name: "dest", label: "Where to keep the backup", type: "select", options, value: options[0][0], onchange: (d) => { show("peerId", d === "id"); show("localPath", d === "local"); } },
      { name: "peerId", label: "Instance id", placeholder: "64-character id", hidden: options[0][0] !== "id", hint: "Ask the owner to run “kinvault id” or look in their Settings." },
      { name: "localPath", label: "Backup folder", type: "folders", hidden: options[0][0] !== "local" },
      { name: "keep", label: "Old versions to keep", type: "select", value: "recommended", options: [
        ["recommended", "Recommended"],
        ["month", "Daily for a month, then monthly for a year"],
        ["all", "Every version (uses the most space)"],
      ], hint: "Recommended keeps the latest 10, hourly versions for a day, daily for two weeks, then weekly, monthly and yearly ones." },
      { name: "rate", label: "Upload speed limit (MB/s)", type: "number", min: "0", step: "any", placeholder: "No limit" },
      { type: "pair", fields: [
        { name: "from", label: "Back up automatically from", type: "time", hint: "Leave empty for any time" },
        { name: "to", label: "until", type: "time" },
      ] },
      { name: "pass", label: "Recovery passphrase", type: "password", hint: "Protects this backup's recovery file. At least 8 characters." },
      { name: "pass2", label: "Repeat passphrase", type: "password" },
    ],
    ok: "Start backing up",
    validate: (v) => {
      if (!v.name) return "Give the backup a name.";
      if (!v.paths.length) return "Choose at least one folder to back up.";
      if (v.dest === "id" && !/^[0-9a-f]{64}$/i.test(v.peerId)) return "Paste the 64-character instance id.";
      if (v.dest === "local" && !v.localPath.length) return "Choose the backup folder.";
      if (v.pass.length < 8) return "The passphrase needs at least 8 characters.";
      if (v.pass !== v.pass2) return "The passphrases don't match.";
      return windowProblem(v);
    },
    onSubmit: async (v) => {
      const target = v.dest === "local" ? { kind: "local", path: v.localPath[0] }
        : { kind: "peer", id: v.dest === "id" ? v.peerId.toLowerCase() : v.dest.slice(5), addrs: [] };
      const retention = { recommended: null, all: {}, month: { last: 3, daily: 31, monthly: 12 } }[v.keep];
      await call("create_set", {
        name: v.name, paths: v.paths, target, recovery_passphrase: v.pass,
        debounce_secs: null, rescan_secs: null, upload_limit: toBytes(v.rate, MiB),
        window: windowFrom(v.from, v.to), retention, excludes: excludesFrom(v.excludes),
      });
    },
  });
  if (v) toast("Backup created. Export a recovery kit in Settings so you can restore if this computer is lost.");
}

// ----- restore -----

let snapshotsRequest = 0;

async function loadSnapshots(setId) {
  const request = ++snapshotsRequest;
  state.restoreSet = setId;
  state.snapshotsSet = setId;
  state.selectedSnapshot = null;
  state.snapshots = [];
  state.snapshotsError = null;
  state.snapshotsLoading = true;
  render();
  try {
    const snaps = await call("list_snapshots", { set: setId });
    if (request !== snapshotsRequest) return; // another backup was chosen meanwhile
    state.snapshots = snaps.reverse();
  } catch (e) {
    if (request !== snapshotsRequest) return;
    state.snapshotsError = String(e);
  }
  state.snapshotsLoading = false;
  if (state.page === "restore") render();
}

/** What the versions card shows instead of the table, if anything. */
function snapshotsNotice(set) {
  if (state.snapshotsLoading) {
    const from = set?.target.kind === "peer" ? ` from ${peerName(set.target.id)}` : "";
    return el("div", { class: "muted" }, `Loading versions${from}…`);
  }
  if (state.snapshotsError) {
    const offline = set?.target.kind === "peer"
      ? ` Check that ${peerName(set.target.id)} is switched on and connected, then try again.` : "";
    return el("div", { class: "notice bad" }, `Couldn't load the versions: ${state.snapshotsError}.${offline}`);
  }
  if (!state.snapshots.length) return el("div", { class: "muted" }, "No versions yet. They appear after the first backup finishes.");
  return null;
}

function renderRestore() {
  const page = document.getElementById("page-restore");
  page.replaceChildren(el("div", { class: "page-head" }, el("h1", {}, "Restore")));
  for (const job of restoreJobs()) page.append(restoreCard(job));
  const sets = restorableSets();
  if (!sets.length) {
    page.append(el("div", { class: "card empty" }, "There's nothing to restore yet."));
    return;
  }
  if (!sets.some((s) => s.id === state.restoreSet)) {
    loadSnapshots(sets[0].id);
    return;
  }
  const picker = el("select", { onchange: (e) => loadSnapshots(e.target.value) },
    sets.map((s) => el("option", { value: s.id, selected: s.id === state.restoreSet },
      s.stopped_unix ? `${s.name} (stopped)` : s.name)));
  page.append(el("div", { class: "card" }, el("div", { class: "field", style: "margin-top:0" }, el("label", {}, "Backup"), picker)));

  const table = el("table", {}, el("thead", {}, el("tr", {}, el("th", {}, "Version from"), el("th", {}, "Computer"), el("th", {}, "Files"), el("th", {}, "Size"))));
  const tbody = el("tbody");
  for (const s of state.snapshots) {
    tbody.append(el("tr", {
      class: s.id === state.selectedSnapshot ? "selectable selected" : "selectable",
      onclick: () => { state.selectedSnapshot = s.id; render(); },
    }, el("td", {}, dateTime(s.time_ns / 1e9)), el("td", {}, s.hostname), el("td", {}, s.file_count), el("td", {}, bytes(s.total_bytes))));
  }
  table.append(tbody);
  const notice = snapshotsNotice(sets.find((s) => s.id === state.restoreSet));
  const retry = state.snapshotsLoading ? null
    : el("button", { class: "btn", onclick: () => loadSnapshots(state.restoreSet) }, state.snapshotsError ? "Try again" : "Refresh");
  page.append(el("div", { class: "card" },
    notice || table,
    el("div", { class: "actions" },
      el("button", { class: "btn primary", disabled: !state.selectedSnapshot, onclick: restoreDialog }, "Restore this version…"),
      retry)));
}

async function restoreDialog() {
  const snap = state.snapshots.find((s) => s.id === state.selectedSnapshot);
  const v = await form({
    title: "Restore",
    intro: `Version from ${dateTime(snap.time_ns / 1e9)}. Files are recreated inside the folder you choose, under their original paths. Nothing is overwritten outside it.`,
    fields: [
      { name: "target", label: "Restore into", type: "folders" },
      { name: "include", label: "Only this file or folder (optional)", placeholder: snap.paths[0]?.replace(/^\/+/, "") || "", hint: "As stored in the backup, e.g. home/me/Documents/taxes. Leave empty for everything." },
    ],
    ok: "Restore",
    validate: (v) => (v.target.length ? null : "Choose where to restore to."),
    onSubmit: async (v) => {
      await call("start_restore", { set: state.restoreSet, snapshot: snap.id, target: v.target[0], include: v.include || null });
    },
  });
  if (v) toast("Restoring in the background. You can keep using KinVault meanwhile.");
  return v;
}

// ----- background restores -----

function restoreJobs() {
  return state.status?.restores || [];
}

function restorePercent(job) {
  if (!job.total_bytes) return job.total_files ? Math.floor((100 * job.files) / job.total_files) : 0;
  return Math.min(100, Math.floor((100 * job.bytes) / job.total_bytes));
}

function restoreText(job) {
  if (!job.total_files && !job.files) return "Starting…";
  return `${job.files} of ${plural(job.total_files, "file")} · ${bytes(job.bytes)} of ${bytes(job.total_bytes)} · ${restorePercent(job)}%`;
}

function restoreCard(job) {
  const cancel = el("button", { class: "btn small" }, "Cancel");
  cancel.addEventListener("click", () => attempt(() => call("cancel_restore", { id: job.id }), cancel));
  return el("div", { class: "card", id: `restore-${job.id}` },
    el("div", { class: "card-head" }, el("span", { class: "card-title" }, `Restoring ${job.set_name}`), el("span", { class: "spacer" }), cancel),
    el("div", { class: "muted small" }, `Into ${job.target}`),
    el("div", { class: "progress" }, el("div", { class: "bar", style: `width:${restorePercent(job)}%` })),
    el("div", { class: "muted small text", style: "margin-top:6px" }, restoreText(job)));
}

/** Shows a restore's latest progress without redrawing the page. */
function updateRestore(job) {
  const jobs = state.status?.restores;
  if (!jobs) return;
  const i = jobs.findIndex((j) => j.id === job.id);
  if (i < 0) jobs.push(job); else jobs[i] = job;
  const card = document.getElementById(`restore-${job.id}`);
  if (card) {
    card.querySelector(".bar").style.width = `${restorePercent(job)}%`;
    card.querySelector(".text").textContent = restoreText(job);
  } else if (state.page === "restore") {
    render();
  }
  updateRestoreNav();
}

function restoreEnded(id) {
  if (state.status) state.status.restores = restoreJobs().filter((j) => j.id !== id);
  if (state.page === "restore") render();
  updateRestoreNav();
}

/** The Restore menu item shows progress while a restore runs. */
function updateRestoreNav() {
  const item = document.querySelector('.nav-item[data-page="restore"]');
  const jobs = restoreJobs();
  item.textContent = jobs.length ? `Restore · ${restorePercent(jobs[0])}%` : "Restore";
}

// ----- friends -----

function renderFriends() {
  const page = document.getElementById("page-friends");
  const invite = el("button", { class: "btn primary", disabled: !state.connected, onclick: inviteDialog }, "Invite a friend");
  const join = el("button", { class: "btn", disabled: !state.connected, onclick: joinDialog }, "Join with a code");
  page.replaceChildren(el("div", { class: "page-head" }, el("h1", {}, "Friends"), el("div", { class: "row" }, join, invite)));
  page.append(el("p", { class: "muted" },
    "Friends can keep encrypted backups on each other's computers. They can't read what you store, and you can't read theirs."));

  const friends = state.peers.filter((p) => !p.mine);
  if (!friends.length) {
    page.append(el("div", { class: "card empty" }, "No friends yet. Invite someone, or join with a code a friend sent you."));
  }
  for (const p of friends) {
    const lines = el("div", { class: "lines" });
    if (p.grant) {
      const quota = p.grant.quota_bytes;
      lines.append(el("div", {}, `Stores backups here: ${bytes(p.used_bytes)} used of ${describeGrant(p.grant)}${deletingNote(p)}`));
      if (quota) lines.append(el("div", { class: "progress" }, el("div", { style: `width:${Math.min(100, (100 * p.used_bytes) / quota).toFixed(1)}%` })));
    } else {
      lines.append(el("div", { class: "muted" }, notAllowed(p)));
    }
    lines.append(el("div", {}, p.hosts_us
      ? `Keeps your backups: up to ${bytes(p.hosts_us.quota_bytes)}`
      : el("span", { class: "muted" }, "Doesn't keep your backups")));
    const edit = el("button", { class: "btn small", onclick: () => limitsDialog(p) }, p.grant ? "Change limits…" : "Allow to store here…");
    const revoke = p.grant ? el("button", { class: "btn small danger", onclick: () => revokeDialog(p) }, "Stop hosting…") : null;
    const toMine = el("button", { class: "btn small", onclick: () => moveToMineDialog(p) }, "Move to Mine…");
    page.append(el("div", { class: "card" },
      el("div", { class: "card-head" }, el("span", { class: "card-title" }, p.name || "Unnamed friend"), el("span", { class: "spacer" }),
        el("span", { class: "mono muted", title: p.id }, shortId(p.id))),
      lines, el("div", { class: "actions" }, edit, toMine, revoke)));
  }
  renderInvites(page, state.invites.filter((i) => !i.mine));
}

function renderInvites(page, invites) {
  if (invites.length) {
    page.append(el("h2", {}, "Invites waiting to be used"));
    for (const i of invites) {
      const cancel = el("button", { class: "btn small" }, "Cancel");
      cancel.addEventListener("click", () => attempt(() => call("cancel_invite", { id: i.id }), cancel));
      page.append(el("div", { class: "card row" },
        el("span", { class: "spacer" }, i.mine ? `${i.name || "Invite"} · one of your devices`
          : `${i.name || "Invite"} · ${describeGrant(i.grant)}${i.ask_reciprocal ? " · asks for storage back" : ""}`,
          el("div", { class: "muted small" }, `Expires ${dateTime(i.expires_unix)}`)),
        cancel));
    }
  }
}

// ----- mine -----

function renderMine() {
  const page = document.getElementById("page-mine");
  const add = el("button", { class: "btn primary", disabled: !state.connected, onclick: addDeviceDialog }, "Add a device");
  const join = el("button", { class: "btn", disabled: !state.connected, onclick: () => joinDialog(true) }, "Join with a code");
  const looking = !!state.nearby.until_unix;
  const find = el("button", { class: "btn", disabled: !state.connected || looking }, "Find nearby devices");
  find.addEventListener("click", () => attempt(async () => { state.nearby = await call("find_nearby"); render(); }, find));
  page.replaceChildren(el("div", { class: "page-head" }, el("h1", {}, "Mine"), el("div", { class: "row" }, find, join, add)));
  page.append(el("p", { class: "muted" },
    "Your own computers and servers. They keep each other's backups without storage, speed or time limits."));
  if (looking) page.append(nearbyCard());

  const mine = state.peers.filter((p) => p.mine);
  if (!mine.length) {
    page.append(el("div", { class: "card empty" },
      "No devices yet. Choose “Add a device” here, then “Join with a code” on Mine on the other device."));
  }
  for (const p of mine) {
    const lines = el("div", { class: "lines" });
    lines.append(p.grant
      ? el("div", {}, `Stores backups here: ${bytes(p.used_bytes)}${deletingNote(p)}`)
      : el("div", { class: "muted" }, notAllowed(p)));
    const using = setsOn(p.id);
    lines.append(using.length
      ? el("div", {}, `Keeps your backups: ${using.map((s) => s.name).join(", ")}`)
      : p.hosts_us
        ? el("div", {}, "Can keep your backups")
        : el("div", { class: "muted" }, "Doesn't keep your backups"));
    const remove = el("button", {
      class: "btn small danger", disabled: using.length > 0, onclick: () => removeDeviceDialog(p),
      title: using.length ? "Delete the backups it keeps first" : null,
    }, "Remove…");
    const toFriends = el("button", { class: "btn small" }, "Move to Friends");
    toFriends.addEventListener("click", () => attempt(async () => {
      await call("peer_set_mine", { id: p.id, mine: false });
      toast(`${p.name || "Device"} moved to Friends. Set its limits there if you want any.`);
    }, toFriends));
    const allow = p.grant ? null : el("button", { class: "btn small" }, "Allow to store here");
    allow?.addEventListener("click", () => attempt(() => call("peer_set_mine", { id: p.id, mine: true }), allow));
    page.append(el("div", { class: "card" },
      el("div", { class: "card-head" }, el("span", { class: "card-title" }, p.name || "Unnamed device"), el("span", { class: "spacer" }),
        el("span", { class: "mono muted", title: p.id }, shortId(p.id))),
      lines, el("div", { class: "actions" }, allow, toFriends, remove),
      using.length ? el("div", { class: "muted small", style: "margin-top:6px" },
        `To remove it, first delete the backups it keeps (Backups → Settings… → Delete permanently).`) : null));
  }
  renderInvites(page, state.invites.filter((i) => i.mine));
}

/** Backup sets stored on this peer. */
function setsOn(id) {
  return restorableSets().filter((s) => s.target.kind === "peer" && s.target.id === id);
}

async function removeDeviceDialog(peer) {
  const name = peer.name || "this device";
  const stored = peer.used_bytes ? ` What it stored here (${bytes(peer.used_bytes)}) is erased in a week.` : "";
  if (!await confirmDialog(`Remove ${name}?`,
    `It will no longer be able to store backups here.${stored} To use it again later, pair it again.`,
    "Remove")) return;
  if (await attempt(() => call("peer_remove", { id: peer.id }))) toast(`${name} removed.`);
}

function secondsLeft() {
  return Math.max(0, Math.round(state.nearby.until_unix - Date.now() / 1000));
}

function countdown() {
  const s = secondsLeft();
  return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")} left`;
}

function nearbyCard() {
  const stop = el("button", { class: "btn small" }, "Stop");
  stop.addEventListener("click", () => attempt(async () => { await call("stop_nearby"); await refreshNearby(); }, stop));
  const card = el("div", { class: "card" },
    el("div", { class: "card-head" }, el("span", { class: "card-title" }, "Looking for your devices on this network"),
      el("span", { class: "spacer" }), el("span", { class: "muted small", id: "nearby-left" }, countdown()), stop),
    el("div", { class: "muted small" }, "Choose “Find nearby devices” on your other device too. Both need to be on the same network."));
  const devices = state.nearby.devices;
  if (!devices.length) card.append(el("div", { class: "lines" }, el("div", { class: "muted" }, "Nothing found yet…")));
  for (const d of devices) {
    let action;
    if (d.state === "paired") action = el("span", { class: "chip ok" }, "Yours");
    else if (d.state === "waiting") action = el("span", { class: "chip" }, `Now confirm on ${d.name}`);
    else action = el("button", { class: "btn primary small", onclick: () => pairDialog(d) }, "Add…");
    card.append(el("div", { class: "row", style: "margin-top:12px" },
      el("span", { class: "spacer" }, el("strong", {}, d.name), el("div", { class: "muted small" }, `Code ${d.code}`)), action));
  }
  return card;
}

async function pairDialog(device) {
  const v = await form({
    title: `Add ${device.name}?`,
    intro: `Check that ${device.name} shows the code ${device.code} for this computer. If it doesn't, or it isn't your own device, cancel.`,
    fields: [{ type: "custom", node: el("div", { class: "pair-code" }, device.code) }],
    ok: "The codes match, add it",
    onSubmit: async () => { state.nearby = await call("pair_nearby", { id: device.id }); },
  });
  if (!v) return;
  const now = state.nearby.devices.find((d) => d.id === device.id);
  toast(now?.state === "paired" ? `${device.name} is now one of your devices.` : `Now add this computer on ${device.name} to finish.`);
  render();
}

async function addDeviceDialog() {
  let code = null;
  const v = await form({
    title: "Add a device",
    intro: "Creates a one-time code for another of your own devices. Both devices can then keep each other's backups without limits.",
    fields: [
      { name: "name", label: "Device name", placeholder: "e.g. Laptop" },
      { name: "days", label: "Code valid for (days)", type: "number", min: "1", value: "7" },
    ],
    ok: "Create code",
    onSubmit: async (v) => {
      const r = await call("create_invite", {
        name: v.name || null, grant: { quota_bytes: null, upload_limit: null, window: null }, ask_reciprocal: true,
        expires_secs: Math.max(1, Number(v.days) || 7) * 86400, mine: true,
      });
      code = r.ticket;
    },
  });
  if (v && code) showCode(code, true);
}

async function moveToMineDialog(peer) {
  if (!await confirmDialog(`Move ${peer.name || "this friend"} to Mine?`,
    "Only do this for your own devices. It will be able to store backups here without storage, speed or time limits.",
    "Move to Mine", false)) return;
  await attempt(() => call("peer_set_mine", { id: peer.id, mine: true }));
}

// ----- friends (continued) -----

async function inviteDialog() {
  let code = null;
  const v = await form({
    title: "Invite a friend",
    intro: "Creates a one-time code. Send it to your friend however you like; it works once and expires.",
    fields: [
      { name: "name", label: "Friend's name", placeholder: "e.g. Sam" },
      ...grantFields({ quota_bytes: 100 * GiB }),
      { name: "ask", label: "Ask them to keep my backups too", type: "checkbox", value: true },
      { name: "days", label: "Code valid for (days)", type: "number", min: "1", value: "7" },
    ],
    ok: "Create code",
    validate: windowProblem,
    onSubmit: async (v) => {
      const r = await call("create_invite", {
        name: v.name || null, grant: grantFrom(v), ask_reciprocal: v.ask,
        expires_secs: Math.max(1, Number(v.days) || 7) * 86400,
      });
      code = r.ticket;
    },
  });
  if (v && code) showCode(code);
}

function showCode(code, mine = false) {
  const area = el("textarea", { readonly: true });
  area.value = code;
  const copy = el("button", { class: "btn", type: "button" }, "Copy");
  copy.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(code);
      copy.textContent = "Copied";
    } catch {
      area.select();
    }
  });
  form({
    title: mine ? "Use this code on your other device" : "Send this code to your friend",
    intro: mine ? "On that device, open KinVault → Mine → Join with a code, and paste it."
      : "They open KinVault → Friends → Join with a code, and paste it.",
    fields: [{ type: "custom", node: el("div", { class: "code-box" }, area, copy) }],
    ok: "Done",
  });
}

async function joinDialog(mine = false) {
  let result = null;
  const v = await form({
    title: mine ? "Join one of your devices" : "Join with a code",
    intro: mine ? "Paste the code from “Add a device” on your other device. Each will keep the other's backups without limits." : null,
    fields: [
      { name: "code", label: "Invite code", type: "textarea", placeholder: "kvinvite1…" },
      { name: "name", label: mine ? "What to call this device (optional)" : "What to call this friend (optional)" },
      ...(mine ? [] : [
        { name: "offer", label: "Let them keep their backups here too", type: "checkbox", value: true },
        { name: "quota", label: "Storage you offer them (GB)", type: "number", min: "0", step: "any", placeholder: "Unlimited", value: "100" },
      ]),
    ],
    ok: "Join",
    validate: (v) => (v.code.startsWith("kvinvite1") ? null : "That doesn't look like a KinVault invite code."),
    onSubmit: async (v) => {
      const offer = v.offer ? { quota_bytes: toBytes(v.quota, GiB), upload_limit: null, window: null } : null;
      result = await call("redeem_invite", { ticket: v.code, name: v.name || null, offer, mine });
    },
  });
  if (!v || !result) return;
  if (mine) {
    toast(`${result.host_name} added to Mine. Create a backup to use it.`);
    return;
  }
  toast(`You joined ${result.host_name}: you can store ${bytes(result.quota_bytes)} there. Create a backup to use it.`);
  if (result.ask_reciprocal && !v.offer) {
    toast(`${result.host_name} asked to keep their backups here too. Use “Allow to store here” on their card if you agree.`);
  }
}

async function limitsDialog(peer) {
  const v = await form({
    title: peer.grant ? `Limits for ${peer.name || "this friend"}` : `Let ${peer.name || "this friend"} store backups here`,
    fields: grantFields(peer.grant || {}),
    ok: "Save",
    validate: windowProblem,
    onSubmit: (v) => call("peer_allow", { id: peer.id, name: null, grant: grantFrom(v) }),
  });
  if (v) toast("Saved");
}

async function revokeDialog(peer) {
  if (!await confirmDialog(`Stop hosting ${peer.name || "this friend"}?`,
    "They won't be able to add new backups here. What they already stored is kept until you delete it.", "Stop hosting")) return;
  await attempt(() => call("peer_revoke", { id: peer.id }));
}

// ----- settings -----

function renderSettings() {
  const page = document.getElementById("page-settings");
  page.replaceChildren(el("div", { class: "page-head" }, el("h1", {}, "Settings")));
  const s = state.status;

  const autostart = el("input", { type: "checkbox", checked: state.autostart });
  autostart.addEventListener("change", () => attempt(async () => {
    await invoke("set_autostart", { enabled: autostart.checked });
    state.autostart = autostart.checked;
    toast(autostart.checked ? "KinVault now starts when you log in." : "KinVault won't start at login.");
  }).finally(async () => {
    state.autostart = await invoke("autostart_enabled");
    autostart.checked = state.autostart;
  }));

  const general = WEB
    ? el("div", { class: "card kv" },
      el("div", { class: "muted" }, "Web interface"),
      el("div", { class: "row" }, el("span", { class: "spacer" }, state.connected ? "Connected" : "Reconnecting…"),
        el("button", { class: "btn small", onclick: () => window.kinvaultSignOut() }, "Sign out")))
    : el("div", { class: "card kv" },
      el("div", { class: "muted" }, "Background service"),
      el("div", {}, state.connected ? "Running" : "Not running"),
      el("div", { class: "muted" }, "Start at login"),
      el("label", { class: "toggle" }, autostart, "Run KinVault in the background whenever I log in"));
  page.append(general);

  if (s) {
    const name = el("input", { type: "text", value: s.name });
    const save = el("button", { class: "btn small" }, "Save");
    save.addEventListener("click", () => attempt(async () => {
      await call("set_instance_name", { name: name.value });
      toast("Name saved");
    }, save));
    const copyId = el("button", { class: "btn small" }, "Copy");
    copyId.addEventListener("click", () => navigator.clipboard.writeText(s.id).then(() => (copyId.textContent = "Copied")));
    page.append(el("h2", {}, "This computer"), el("div", { class: "card kv" },
      el("div", { class: "muted" }, "Name friends see"), el("div", { class: "row" }, el("div", { class: "spacer" }, name), save),
      el("div", { class: "muted" }, "Instance id"), el("div", { class: "row" }, el("span", { class: "mono spacer" }, s.id), copyId),
      el("div", { class: "muted" }, "Friends' backups stored in"), el("div", { class: "mono" }, s.hosting_store),
      el("div", { class: "muted" }, "Version"), el("div", {}, s.version)));
  }

  const n = state.network;
  if (n) {
    const hosts = n.public_hosts.length
      ? el("div", {}, ...n.public_hosts.map((h) => el("div", { class: "mono" }, h)))
      : el("div", { class: "muted" }, "None (only addresses found automatically)");
    const port = el("div", {},
      n.listen_port ? `${n.listen_port} (UDP)` : "Random",
      el("div", { class: "muted small" }, `Listening on ${n.bound.join(", ")}`),
      n.restart_required ? el("div", { class: "muted small" }, "The new port is used once the background service restarts.") : null);
    page.append(el("h2", {}, "Network"), el("div", { class: "card kv" },
      el("div", { class: "muted" }, "Listening port"), port,
      el("div", { class: "muted" }, "Addresses in invite codes"), hosts,
      el("div", {}), el("div", { class: "actions" }, el("button", { class: "btn small", onclick: networkDialog }, "Change…"))));
  }

  if (s) {
    page.append(el("h2", {}, "Deleted data"), el("div", { class: "card kv" },
      el("div", { class: "muted" }, "Keep for"),
      el("div", {}, plural(s.keep_deleted_days, "day"),
        el("div", { class: "muted small" }, "Backups you stop can be restored for this long. What friends delete here is kept this long too, and still counts toward their storage.")),
      el("div", {}), el("div", { class: "actions" }, el("button", { class: "btn small", onclick: graceDialog }, "Change…"))));
  }

  page.append(el("h2", {}, "Recovery"));
  const exportBtn = el("button", { class: "btn primary", disabled: !state.connected, onclick: exportKit }, "Export recovery kit…");
  const importBtn = WEB ? null : el("button", { class: "btn", disabled: state.connected, onclick: importKit }, "Import recovery kit…");
  page.append(el("div", { class: "card" },
    el("p", { style: "margin-top:0" },
      "A recovery kit lets a new computer take over these backups if this one is lost. ",
      "It's protected by a passphrase. Keep it somewhere other than this computer, and export again after adding backups."),
    el("div", { class: "actions" }, exportBtn, importBtn),
    WEB ? el("div", { class: "muted small", style: "margin-top:8px" },
      "To set up a new server from a kit, import it with the kinvault command before the server first starts (see the README).")
    : state.connected ? el("div", { class: "muted small", style: "margin-top:8px" },
      "To import a kit on a new computer, do it before the background service first starts (stop it if it's running).") : null));
}

async function graceDialog() {
  const v = await form({
    title: "Keep deleted data",
    intro: "How long to keep backups you stop, so you can still restore from them, and data friends delete from this computer, " +
      "so a problem on their side can't wipe their history at once. After that, it's erased.",
    fields: [{ name: "days", label: "Days", type: "number", min: "0", max: "3650", step: "1", value: state.status.keep_deleted_days }],
    ok: "Save",
    validate: (v) => (/^\d+$/.test(v.days) && Number(v.days) <= 3650 ? null : "Enter a whole number of days, from 0 to 3650."),
    onSubmit: (v) => call("set_keep_deleted_days", { days: Number(v.days) }),
  });
  if (v) toast("Saved");
}

async function networkDialog() {
  const n = state.network;
  const v = await form({
    title: "Network",
    intro: "Invite codes include the addresses KinVault finds by itself. If friends can reach this computer some other way, " +
      "such as a static IP or a dynamic DNS name with a port forwarded on your router, add it here.",
    fields: [
      { name: "port", label: "Listening port (UDP)", type: "number", min: "1", step: "1", placeholder: "Random", value: n.listen_port ?? "",
        hint: "Pick a fixed port to forward it on your router. Takes effect when the background service restarts." },
      { name: "hosts", label: "Extra addresses, one per line", type: "textarea", placeholder: "home.example.org\n203.0.113.7:4433", value: n.public_hosts.join("\n"),
        hint: "IP addresses or domain names, optionally with :port (the listening port is used otherwise). Domains are looked up on every connection, so dynamic DNS works." },
    ],
    ok: "Save",
    validate: (v) => {
      if (v.port === "") return null;
      const p = Number(v.port);
      return Number.isInteger(p) && p >= 1 && p <= 65535 ? null : "The port must be a whole number from 1 to 65535.";
    },
    onSubmit: async (v) => {
      state.network = await call("set_network", {
        listen_port: v.port === "" ? null : Number(v.port),
        public_hosts: v.hosts.split("\n").map((h) => h.trim()).filter(Boolean),
      });
    },
  });
  if (v) {
    const hasPort = (h) => /^\[.*\]:\d+$/.test(h) || (/:\d+$/.test(h) && h.split(":").length === 2);
    const portless = state.network.public_hosts.some((h) => !hasPort(h));
    toast(portless && !state.network.listen_port
      ? "Saved. Addresses without a port use the listening port, which is random until you set one."
      : "Network settings saved.");
    render();
  }
}

async function exportKit() {
  let saved = null;
  const v = await form({
    title: "Export recovery kit",
    intro: "Choose a passphrase. You'll need it, and the kit file, to restore on another computer.",
    fields: [
      { name: "pass", label: "Passphrase", type: "password" },
      { name: "pass2", label: "Repeat passphrase", type: "password" },
    ],
    ok: "Choose where to save…",
    validate: (v) => (v.pass.length < 8 ? "Use at least 8 characters." : v.pass !== v.pass2 ? "The passphrases don't match." : null),
    onSubmit: async (v) => {
      saved = await invoke("export_recovery_kit", { passphrase: v.pass });
      if (!saved) return false;
    },
  });
  if (v && saved) toast(`Recovery kit saved to ${saved}`);
}

async function importKit() {
  let sets = null;
  const v = await form({
    title: "Import recovery kit",
    intro: "This computer takes over the identity and backups in the kit. Make sure the old computer is no longer running KinVault.",
    fields: [{ name: "pass", label: "Kit passphrase", type: "password" }],
    ok: "Choose kit file…",
    onSubmit: async (v) => {
      sets = await invoke("import_recovery_kit", { passphrase: v.pass });
      if (!sets) return false;
    },
  });
  if (v && sets) toast(`Imported: ${sets.join(", ")}. Start the service, restore what you need, then resume each backup.`);
}

// ---------- navigation and events ----------

function go(page) {
  state.page = page;
  for (const b of document.querySelectorAll(".nav-item")) b.classList.toggle("active", b.dataset.page === page);
  if (page === "mine" || page === "friends" || page === "backups") refreshPeers();
  if (page === "mine") refreshNearby();
  // Load the chosen backup's versions unless they're already shown (e.g. a card's Restore… chose another).
  if (page === "restore" && state.restoreSet && (state.snapshotsError || state.snapshotsSet !== state.restoreSet)) {
    loadSnapshots(state.restoreSet);
  }
  if (page === "settings") refreshNetwork();
  render();
  document.getElementById("main").scrollTop = 0;
}

for (const b of document.querySelectorAll(".nav-item")) b.addEventListener("click", () => go(b.dataset.page));

async function setConnected(connected) {
  state.connected = connected;
  if (connected) {
    await Promise.all([refreshStatus(), refreshPeers(), refreshNetwork(), refreshNearby()]);
  } else {
    state.status = null;
    state.network = null;
    state.nearby = { until_unix: null, devices: [] };
    state.progress = {};
  }
  render();
}

listen("daemon-connection", (e) => setConnected(e.payload));
listen("daemon-event", (e) => {
  const ev = e.payload;
  switch (ev.event) {
    case "progress":
      state.progress[ev.set] = ev;
      if (state.page === "backups") renderBackups();
      break;
    case "set_state": {
      const set = state.status?.sets.find((s) => s.id === ev.set);
      if (set) set.state = ev.state;
      if (ev.state !== "running") delete state.progress[ev.set];
      render();
      refreshSoon();
      break;
    }
    case "backup_failed": {
      const set = state.status?.sets.find((s) => s.id === ev.set);
      toast(`${set?.name || "Backup"} failed: ${ev.error}`, true);
      refreshSoon();
      break;
    }
    case "peers_changed":
      refreshPeers();
      break;
    case "network_changed":
      refreshNetwork();
      break;
    case "nearby_changed":
      refreshNearby();
      break;
    case "restore_progress":
      updateRestore(ev);
      break;
    case "restore_finished": {
      const job = restoreJobs().find((j) => j.id === ev.id);
      restoreEnded(ev.id);
      toast(`Restored ${plural(ev.summary.files, "file")} (${bytes(ev.summary.bytes)})${job ? ` to ${job.target}` : ""}.`);
      break;
    }
    case "restore_failed":
      restoreEnded(ev.id);
      toast(ev.cancelled ? "Restore cancelled. Files restored so far were kept." : `Restore failed: ${ev.error}`, !ev.cancelled);
      break;
    default:
      refreshSoon();
  }
});

// The time left to find nearby devices counts down.
setInterval(() => {
  if (!state.nearby.until_unix) return;
  if (secondsLeft() === 0) refreshNearby();
  const left = document.getElementById("nearby-left");
  if (left) left.textContent = countdown();
}, 1000);

// Open info tips follow their ⓘ when a dialog scrolls or the window resizes.
for (const ev of ["scroll", "resize"]) {
  window.addEventListener(ev, () => {
    for (const tip of document.querySelectorAll(".info-tip")) if (tip.offsetParent || tip.offsetHeight) tip.place?.();
  }, true);
}

// Relative times ("5 min ago") stay fresh.
setInterval(() => { if (state.page === "backups") renderBackups(); }, 30_000);

(async () => {
  state.autostart = await invoke("autostart_enabled").catch(() => false);
  await setConnected(await invoke("daemon_running").catch(() => false));
})();
