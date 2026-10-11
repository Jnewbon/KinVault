// Stands in for the Tauri bridge when the UI is served by `kinvaultd --web`:
// daemon calls go over HTTP, events arrive as server-sent events, and the
// folder picker browses the server's (container's) file system.
"use strict";

(() => {
  window.KINVAULT_WEB = true;

  async function api(path, body) {
    const res = await fetch(path, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-KinVault": "1" },
      body: JSON.stringify(body ?? {}),
    });
    if (res.status === 401) {
      location.reload(); // session expired: back to the sign-in page
      throw "Signed out";
    }
    const text = await res.text();
    if (!res.ok) throw text || `Request failed (${res.status})`;
    return text ? JSON.parse(text) : null;
  }

  function el(tag, attrs, ...children) {
    const node = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (k === "class") node.className = v;
      else if (k.startsWith("on")) node.addEventListener(k.slice(2), v);
      else node.setAttribute(k, v);
    }
    for (const c of children) if (c != null) node.append(c instanceof Node ? c : document.createTextNode(String(c)));
    return node;
  }

  /// A folder browser over the server's file system. Resolves to the chosen
  /// paths, or [] if cancelled.
  function pickFolders(multiple) {
    const dialog = el("dialog", { class: "folder-browser" });
    document.body.append(dialog);
    const chosen = [];
    const pathInput = el("input", { type: "text", autocomplete: "off", spellcheck: "false" });
    const list = el("div", { class: "list-box folder-list" });
    const picked = el("div", { class: "muted small" });
    const error = el("div", { class: "form-error", hidden: "" });

    async function open(path) {
      try {
        const dir = await api("/api/list-dir", { path });
        error.hidden = true;
        pathInput.value = dir.path;
        const rows = [];
        if (dir.parent) rows.push(el("div", { class: "item link", onclick: () => open(dir.parent) }, el("span", {}, "⬑ ..")));
        for (const name of dir.dirs) {
          const full = dir.path.endsWith("/") ? dir.path + name : `${dir.path}/${name}`;
          rows.push(el("div", { class: "item link", onclick: () => open(full) }, el("span", {}, `📁 ${name}`)));
        }
        if (!dir.dirs.length) rows.push(el("div", { class: "item muted" }, "No folders here"));
        list.replaceChildren(...rows);
      } catch (e) {
        error.textContent = String(e);
        error.hidden = false;
      }
    }

    return new Promise((resolve) => {
      const done = (result) => { dialog.close(); dialog.remove(); resolve(result); };
      const showPicked = () => { picked.textContent = chosen.length ? `Chosen: ${chosen.join(", ")}` : ""; };
      const use = el("button", { class: "btn primary", type: "button" }, multiple ? "Add this folder" : "Use this folder");
      use.addEventListener("click", () => {
        const path = pathInput.value.trim();
        if (!path) return;
        if (!multiple) return done([path]);
        if (!chosen.includes(path)) chosen.push(path);
        showPicked();
      });
      const foot = [el("button", { class: "btn", type: "button", onclick: () => done([]) }, "Cancel"), use];
      // "Done" with nothing added yet takes the folder being shown.
      const finish = () => done(chosen.length ? chosen : [pathInput.value.trim()].filter(Boolean));
      if (multiple) foot.push(el("button", { class: "btn primary", type: "button", onclick: finish }, "Done"));
      pathInput.addEventListener("keydown", (e) => { if (e.key === "Enter") open(pathInput.value.trim()); });
      dialog.append(
        el("div", { class: "modal-body" },
          el("h3", {}, multiple ? "Choose folders" : "Choose a folder"),
          el("p", { class: "muted" }, "These are folders on the KinVault server. Folders from your NAS only appear here if they're mounted into the container."),
          el("div", { class: "row" }, el("div", { class: "spacer" }, pathInput),
            el("button", { class: "btn small", type: "button", onclick: () => open(pathInput.value.trim()) }, "Go")),
          list, error, picked),
        el("div", { class: "modal-foot" }, ...foot));
      dialog.addEventListener("cancel", (e) => { e.preventDefault(); done([]); });
      dialog.showModal();
      open("");
    });
  }

  function download(name, text) {
    const url = URL.createObjectURL(new Blob([text], { type: "application/json" }));
    const a = el("a", { href: url, download: name });
    document.body.append(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 10_000);
  }

  const commands = {
    daemon_call: ({ request }) => api("/api/call", request),
    daemon_running: () => true,
    start_daemon: () => Promise.reject("The service runs inside the server; restart the container instead."),
    autostart_enabled: () => false,
    set_autostart: () => Promise.reject("Not available in the web interface."),
    pick_folders: ({ multiple }) => pickFolders(multiple),
    export_recovery_kit: async ({ passphrase }) => {
      const reply = await api("/api/call", { method: "export_recovery_kit", params: { passphrase } });
      download("kinvault-recovery-kit.json", reply.RecoveryKit.json);
      return "your browser's downloads";
    },
    import_recovery_kit: () => Promise.reject("Import recovery kits with the kinvault command; see the README."),
  };

  // One event stream shared by all listeners. Connection changes are reported
  // like the desktop app reports the daemon starting and stopping.
  const listeners = { "daemon-event": [], "daemon-connection": [] };
  let source = null;
  function emit(name, payload) {
    for (const cb of listeners[name]) cb({ payload });
  }
  function connect() {
    if (source) return;
    source = new EventSource("/api/events");
    source.addEventListener("open", () => emit("daemon-connection", true));
    source.addEventListener("message", (e) => emit("daemon-event", JSON.parse(e.data)));
    source.addEventListener("error", async () => {
      emit("daemon-connection", false);
      if (source.readyState === EventSource.CLOSED) {
        source = null;
        // Signed out or server gone; check which before retrying.
        const res = await fetch("/api/session").catch(() => null);
        if (res?.status === 401) location.reload();
        else setTimeout(connect, 3000);
      }
    });
  }

  window.__TAURI__ = {
    core: {
      invoke: (cmd, args) => {
        const run = commands[cmd];
        return run ? Promise.resolve().then(() => run(args || {})) : Promise.reject(`unknown command ${cmd}`);
      },
    },
    event: {
      listen: async (name, cb) => {
        listeners[name]?.push(cb);
        connect();
        return () => {};
      },
    },
  };

  window.kinvaultSignOut = async () => {
    await fetch("/api/logout", { method: "POST", headers: { "X-KinVault": "1" } });
    location.reload();
  };
})();
