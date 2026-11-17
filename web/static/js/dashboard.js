/*
Project: ScAnRoIdS Red Team Orchestrator
Module: web/static/js/dashboard.js
Purpose: Offline viewer updates with persistent filters, sorting, evidence and topology.
*/
"use strict";
const $ = (id) => document.getElementById(id);
const key = "scanroids:" + document.body.dataset.session;
let settings = {
  sort: "ip",
  direction: 1,
  search: "",
  protocol: "",
  interesting: false,
  page: 0,
  tab: "results",
};
try {
  Object.assign(settings, JSON.parse(localStorage.getItem(key) || "{}"));
} catch (_) {}
let state = null,
  scrollLogs = true,
  cursor = 0;
const pageSize = 25;
function save() {
  try {
    localStorage.setItem(key, JSON.stringify(settings));
  } catch (_) {}
}
function el(tag, text, cls) {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text;
  if (cls) node.className = cls;
  return node;
}
function fileLink(path, label) {
  const link = el("a", label || path);
  link.href = "/files/" + path.split("/").map(encodeURIComponent).join("/");
  return link;
}
async function copy(text) {
  try {
    if (navigator.clipboard && window.isSecureContext)
      await navigator.clipboard.writeText(text);
    else {
      const area = el("textarea", text);
      document.body.append(area);
      area.select();
      if (!document.execCommand("copy")) throw Error("copy");
      area.remove();
    }
    $("copy-feedback").textContent = "Copied to clipboard.";
  } catch (_) {
    $("copy-feedback").textContent =
      "Copy unavailable. Select the command text to copy it.";
  }
}
function showTab(tab) {
  if (
    ![
      "results",
      "hosts",
      "topology",
      "artifacts",
      "history",
      "analysis",
    ].includes(tab)
  )
    tab = "results";
  settings.tab = tab;
  save();
  document
    .querySelectorAll(".tab-content")
    .forEach((n) => (n.hidden = n.id !== tab));
  document
    .querySelectorAll("[data-tab]")
    .forEach((n) => n.classList.toggle("selected", n.dataset.tab === tab));
  if (tab === "topology") loadTopology();
}
function emptyBody(body, columns, message) {
  const tr = el("tr"),
    td = el("td", message, "empty");
  td.colSpan = columns;
  tr.append(td);
  body.replaceChildren(tr);
}
function ipKey(ip) {
  if (!ip.includes(":"))
    return (
      "4:" +
      ip
        .split(".")
        .map((x) => x.padStart(3, "0"))
        .join(".")
    );
  const halves = ip.split("::"),
    left = halves[0] ? halves[0].split(":") : [],
    right = halves[1] ? halves[1].split(":") : [];
  const parts =
    halves.length === 2
      ? [
          ...left,
          ...Array(Math.max(0, 8 - left.length - right.length)).fill("0"),
          ...right,
        ]
      : left;
  return "6:" + parts.map((x) => x.padStart(4, "0")).join(":");
}
function services() {
  if (!state) return;
  const terms = settings.search
    .toLowerCase()
    .trim()
    .split(/\s+/)
    .filter(Boolean);
  const rows = state.results.filter(
    (row) =>
      (!settings.protocol || row.protocol === settings.protocol) &&
      (!settings.interesting || row.is_interesting) &&
      terms.every((term) =>
        [
          row.ip,
          row.os_guess,
          row.port,
          row.service,
          row.product,
          row.version,
          row.protocol,
        ]
          .join(" ")
          .toLowerCase()
          .includes(term),
      ),
  );
  rows.sort((a, b) => {
    let x = a[settings.sort],
      y = b[settings.sort];
    if (settings.sort === "ip") {
      x = ipKey(x);
      y = ipKey(y);
    }
    const result =
      typeof x === "number"
        ? x - y
        : String(x || "").localeCompare(String(y || ""));
    return (
      settings.direction * result ||
      a.port - b.port ||
      a.protocol.localeCompare(b.protocol)
    );
  });
  settings.page = Math.max(
    0,
    Math.min(
      Number(settings.page) || 0,
      Math.max(0, Math.ceil(rows.length / pageSize) - 1),
    ),
  );
  const body = $("service-rows");
  body.replaceChildren();
  for (const row of rows.slice(
    settings.page * pageSize,
    (settings.page + 1) * pageSize,
  )) {
    const tr = el("tr");
    tr.classList.toggle("interesting", !!row.is_interesting);
    tr.classList.toggle("dc", !!row.is_dc);
    tr.append(el("td", row.ip), el("td", row.os_guess || "Unknown"));
    const port = el("td", `${row.port}/${row.protocol}`);
    if (row.suggestion) {
      const bolt = el("button", "⚡", "bolt");
      bolt.title = "Copy service-specific Nmap command";
      bolt.setAttribute(
        "aria-label",
        `Copy suggested command for ${row.port}/${row.protocol}`,
      );
      bolt.onclick = () => copy(row.suggestion);
      port.append(bolt);
    }
    const service = el("td", row.service);
    service.append(
      el("small", [row.product, row.version].filter(Boolean).join(" ")),
    );
    const distance = el("td", row.ttl ? String(row.ttl) : "Unknown TTL");
    distance.append(
      el(
        "small",
        row.hops === null ? "Distance unknown" : `${row.hops} measured hops`,
      ),
    );
    const shared = el("td");
    shared.append(fileLink("targets/" + row.service_link, "Host list ↗"));
    const evidence = el("td"),
      button = el("button", "Inspect");
    button.onclick = () => {
      $("evidence-title").textContent =
        `${row.ip} · ${row.port}/${row.protocol}`;
      let scripts = [];
      try {
        scripts = JSON.parse(row.scripts || "[]");
      } catch (_) {}
      $("evidence-text").textContent = [
        `${row.service} ${row.product || ""} ${row.version || ""}`,
        `State: ${row.state} · Reason: ${row.reason || "not recorded"}`,
        ...scripts.map((s) => `${s.id}\n${s.output}`),
      ].join("\n\n");
      $("evidence-dialog").showModal();
    };
    evidence.append(button);
    tr.append(
      port,
      service,
      el("td", row.reason || "—"),
      distance,
      shared,
      evidence,
    );
    body.append(tr);
  }
  if (!rows.length)
    emptyBody(
      body,
      8,
      state.results.length
        ? "No services match these filters."
        : "No confirmed open services yet. Discovery-only hosts appear in Hosts.",
    );
  $("result-total").textContent = `(${rows.length})`;
  $("pagination").textContent =
    `${settings.page + 1} / ${Math.max(1, Math.ceil(rows.length / pageSize))}`;
  $("prev").disabled = settings.page === 0;
  $("next").disabled = (settings.page + 1) * pageSize >= rows.length;
  document
    .querySelectorAll("[data-sort]")
    .forEach((n) =>
      n.parentElement.setAttribute(
        "aria-sort",
        n.dataset.sort === settings.sort
          ? settings.direction === 1
            ? "ascending"
            : "descending"
          : "none",
      ),
    );
  save();
}
function render(data) {
  state = data;
  const meta = data.meta;
  $("connection").textContent = "● Viewer connected";
  $("activity").textContent = data.active
    ? "● Scan / tool running"
    : data.jobs.length
      ? "● Scan idle / finished"
      : "● Ready";
  $("activity").className =
    "activity " +
    (data.active ? "running" : data.jobs.length ? "finished" : "");
  $("host-count").textContent = data.hosts.filter(
    (h) => h.state === "up",
  ).length;
  $("service-count").textContent = data.results.length;
  const counts = new Map();
  data.results.forEach((r) => counts.set(r.ip, (counts.get(r.ip) || 0) + 1));
  $("juicy").textContent =
    [...counts].sort((a, b) => b[1] - a[1])[0]?.[0] || "—";
  $("phase").textContent = meta.scan_phase;
  $("status").textContent = meta.status;
  $("operator").textContent = meta.operator;
  $("started").textContent = new Date(meta.start_time).toLocaleString();
  $("command").textContent = meta.nmap_syntax;
  services();
  const hostBody = $("host-rows");
  hostBody.replaceChildren();
  data.hosts.forEach((h) => {
    const tr = el("tr");
    let names = [];
    try {
      names = JSON.parse(h.hostnames);
    } catch (_) {}
    tr.append(
      el("td", h.ip),
      el("td", h.state),
      el("td", h.os || "Unknown"),
      el("td", names.join(", ") || "—"),
      el("td", h.hops === null ? "Unknown" : `${h.hops} hops`),
    );
    hostBody.append(tr);
  });
  if (!data.hosts.length) emptyBody(hostBody, 5, "No hosts recorded yet.");
  const artifact = $("artifact-list");
  artifact.replaceChildren();
  const screenshots = data.artifacts.filter((f) =>
    /\.(png|jpe?g|webp)$/i.test(f.path),
  );
  if (screenshots.length) {
    const gallery = el("a", "Open screenshot gallery ↗");
    gallery.href = "/gallery";
    artifact.append(gallery);
  }
  data.artifacts.forEach((f) => {
    const div = el("div", undefined, "file-row");
    div.append(
      fileLink(f.path),
      el("span", `${(f.size / 1024).toFixed(1)} KB`, "muted small"),
    );
    artifact.append(div);
  });
  if (!data.artifacts.length)
    artifact.append(el("p", "No artifacts yet.", "muted"));
  const jobs = $("job-rows");
  jobs.replaceChildren();
  data.jobs.forEach((job) => {
    const tr = el("tr"),
      link = el("td");
    link.append(fileLink(job.log, "Output ↗"));
    tr.append(
      el("td", new Date(job.started).toLocaleString()),
      el("td", `${job.tool} / ${job.phase}`),
      el("td", job.status),
      el("td", job.returncode === null ? "—" : String(job.returncode)),
      link,
    );
    jobs.append(tr);
  });
  if (!data.jobs.length)
    emptyBody(jobs, 5, "No tool executions in this session.");
  $("import-list").replaceChildren(
    ...data.imports.map((i) =>
      el(
        "p",
        `${i.source} · ${new Date(i.imported).toLocaleString()} · ${i.digest.slice(0, 12)}`,
        "small muted",
      ),
    ),
  );
}
async function refresh() {
  try {
    const response = await fetch("/api/state");
    if (response.status === 401) {
      location.href = "/login";
      return;
    }
    if (!response.ok) throw Error(response.status);
    render(await response.json());
  } catch (_) {
    $("connection").textContent = "● Connection lost — retrying";
    $("activity").textContent = "● Process status unavailable";
    $("activity").className = "activity";
  }
}
async function loadTopology() {
  try {
    const response = await fetch("/api/topology");
    if (!response.ok) throw Error("topology");
    const data = await response.json(),
      view = $("topology-view");
    view.replaceChildren();
    if (!data.nodes.length) {
      view.append(el("p", "No route or target observations yet.", "muted"));
      return;
    }
    // Layer hosts by measured distance. Unknown-distance targets stay in a clearly
    // labeled separate row and never acquire an inferred network edge.
    const groups = new Map();
    data.nodes.forEach((n) => {
      const layer = n.hops === null ? "unknown" : n.hops;
      if (!groups.has(layer)) groups.set(layer, []);
      groups.get(layer).push(n);
    });
    const layers = [...groups.keys()].sort((a, b) =>
        a === "unknown" ? 1 : b === "unknown" ? -1 : a - b,
      ),
      positions = new Map();
    const width = Math.max(
        800,
        ...[...groups.values()].map((v) => v.length * 180 + 160),
      ),
      height = layers.length * 110 + 70;
    const ns = "http://www.w3.org/2000/svg",
      svg = document.createElementNS(ns, "svg");
    svg.setAttribute("viewBox", `0 0 ${width} ${height}`);
    svg.setAttribute("role", "img");
    svg.setAttribute(
      "aria-label",
      "Measured traceroute hops and discovered targets",
    );
    layers.forEach((layer, i) => {
      const label = document.createElementNS(ns, "text");
      label.setAttribute("x", "15");
      label.setAttribute("y", String(60 + i * 110));
      label.textContent = layer === "unknown" ? "No distance" : `Hop ${layer}`;
      svg.append(label);
      groups
        .get(layer)
        .forEach((n, j) =>
          positions.set(n.id, { x: 160 + j * 180, y: 55 + i * 110 }),
        );
    });
    data.edges.forEach((edge) => {
      const a = positions.get(edge.source),
        b = positions.get(edge.target);
      if (!a || !b) return;
      const line = document.createElementNS(ns, "line");
      line.setAttribute("x1", a.x);
      line.setAttribute("y1", a.y);
      line.setAttribute("x2", b.x);
      line.setAttribute("y2", b.y);
      svg.append(line);
    });
    data.nodes.forEach((n) => {
      const p = positions.get(n.id),
        circle = document.createElementNS(ns, "circle");
      circle.setAttribute("cx", p.x);
      circle.setAttribute("cy", p.y);
      circle.setAttribute("r", "8");
      circle.setAttribute("class", n.kind);
      const title = document.createElementNS(ns, "title");
      title.textContent = `${n.id} · ${n.os}`;
      circle.append(title);
      svg.append(circle);
      const label = document.createElementNS(ns, "text");
      label.setAttribute("x", p.x - 48);
      label.setAttribute("y", p.y + 27);
      label.textContent = n.id;
      svg.append(label);
    });
    view.append(svg);
  } catch (_) {
    $("topology-view").replaceChildren(
      el("p", "Topology unavailable. Use Refresh topology to retry.", "muted"),
    );
  }
}
$("search").value = settings.search;
$("protocol").value = settings.protocol;
$("interesting").checked = settings.interesting;
$("search").oninput = (e) => {
  settings.search = e.target.value;
  settings.page = 0;
  services();
};
$("protocol").onchange = (e) => {
  settings.protocol = e.target.value;
  settings.page = 0;
  services();
};
$("interesting").onchange = (e) => {
  settings.interesting = e.target.checked;
  settings.page = 0;
  services();
};
document.querySelectorAll("[data-sort]").forEach(
  (n) =>
    (n.onclick = () => {
      settings.direction =
        settings.sort === n.dataset.sort ? -settings.direction : 1;
      settings.sort = n.dataset.sort;
      services();
    }),
);
document
  .querySelectorAll("[data-tab]")
  .forEach((n) => (n.onclick = () => showTab(n.dataset.tab)));
$("prev").onclick = () => {
  settings.page--;
  services();
};
$("next").onclick = () => {
  settings.page++;
  services();
};
$("copy-command").onclick = () => copy($("command").textContent);
$("close-evidence").onclick = () => $("evidence-dialog").close();
$("refresh-topology").onclick = loadTopology;
$("pause-log").onclick = () => {
  scrollLogs = !scrollLogs;
  $("pause-log").textContent = scrollLogs ? "Pause scroll" : "Resume scroll";
};
const recipes = [
  ["Capture summary", "capinfos '<capture>'"],
  ["Protocol hierarchy", "tshark -r '<capture>' -n -q -z io,phs"],
  ["IP conversations", "tshark -r '<capture>' -n -q -z conv,ip"],
  [
    "DNS questions",
    "tshark -r '<capture>' -n -Y dns.qry.name -T fields -e frame.time -e ip.src -e dns.qry.name",
  ],
  [
    "HTTP requests",
    "tshark -r '<capture>' -n -Y http.request -T fields -e ip.src -e http.host -e http.request.method -e http.request.uri",
  ],
  [
    "TLS handshakes / SNI",
    "tshark -r '<capture>' -n -Y tls.handshake -T fields -e ip.dst -e tls.handshake.type -e tls.handshake.extensions_server_name",
  ],
  ["SMB / RPC", "tshark -r '<capture>' -n -Y 'smb || smb2 || dcerpc'"],
  [
    "ARP discovery",
    "tshark -r '<capture>' -n -Y arp -T fields -e arp.src.proto_ipv4 -e arp.src.hw_mac",
  ],
];
recipes.forEach(([title, command]) => {
  const div = el("div", undefined, "recipe"),
    button = el("button", "Copy");
  button.onclick = () => copy(command);
  div.append(el("h2", title), el("pre", command), button);
  $("analysis-recipes").append(div);
});
const source = new EventSource("/api/events");
source.onmessage = (message) => {
  const record = JSON.parse(message.data);
  if (record.id <= cursor) return;
  cursor = record.id;
  const logs = $("logs");
  const text = record.message.replace(/\x1b\[[0-9;]*[A-Za-z]/g, "");
  logs.textContent = (
    logs.textContent +
    text +
    (text.endsWith("\n") ? "" : "\n")
  ).slice(-100000);
  if (scrollLogs) logs.scrollTop = logs.scrollHeight;
};
showTab(settings.tab);
refresh();
setInterval(refresh, 3000);
/* INPUT: Authenticated state/event APIs. OUTPUT: Persistent, viewing-only dashboard updates. */
