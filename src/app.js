/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * SELinux Fixer — Cockpit page. All real work happens in sefix.py, which is
 * fetched from this package's directory and run with `python3 -c`, so the
 * page works the same whether installed system-wide or in ~/.local.
 */
"use strict";

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));
const esc = s => String(s ?? "").replace(/[&<>"']/g,
    c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

let helperCode = null;
let result = null;          // last scan
let currentTab = "open";
let scanning = false;
const PROMPTED = "sefix:prompted";
const UNDOABLE = ["boolean", "module", "port", "fcontext"];

/* ------------------------------------------------------------------ theme */

function applyTheme() {
    let style = "auto";
    try { style = localStorage.getItem("shell:style") || "auto"; } catch (e) { /* ignore */ }
    const dark = style === "dark" ||
        (style === "auto" && window.matchMedia("(prefers-color-scheme: dark)").matches);
    document.documentElement.classList.toggle("dark", dark);
}
applyTheme();
window.addEventListener("storage", applyTheme);
window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", applyTheme);

/* ----------------------------------------------------------------- helper */

async function loadHelper() {
    if (!helperCode) {
        const r = await fetch("sefix.py");
        if (!r.ok) throw new Error("could not load sefix.py (" + r.status + ")");
        helperCode = await r.text();
    }
    return helperCode;
}

/* Run a helper subcommand and parse its JSON output. */
async function helper(args, { input = null, superuser = "try" } = {}) {
    const code = await loadHelper();
    const proc = cockpit.spawn(["python3", "-c", code, ...args], { err: "message", superuser });
    if (input !== null) proc.input(input);
    const out = await proc;
    return out.trim() ? JSON.parse(out) : {};
}

function errText(ex) {
    if (!ex) return "Unknown error";
    if (ex.problem === "access-denied" || ex.problem === "not-authorized")
        return "Administrative access is required. Turn it on with the " +
               "“Limited access” button at the top of Cockpit, then try again.";
    return String(ex.message || ex.problem || ex).replace(/^selinux-fixer:\s*/, "");
}

/* ------------------------------------------------------------------- misc */

function showAlert(text, kind = "danger") {
    const a = $("#alert");
    a.className = "alert " + kind;
    a.innerHTML = `<span>${esc(text)}</span><button class="link" aria-label="Dismiss">×</button>`;
    a.hidden = false;
    $("button", a).onclick = () => { a.hidden = true; };
}

function confirmDialog(title, text, okLabel, kind = "danger") {
    return new Promise(resolve => {
        $("#confirm-title").textContent = title;
        $("#confirm-text").textContent = text;
        $("#confirm-ok").textContent = okLabel;
        $("#confirm-ok").className = "btn " + kind;
        $("#confirm").hidden = false;
        const done = v => { $("#confirm").hidden = true; resolve(v); };
        $("#confirm-ok").onclick = () => done(true);
        $("#confirm-cancel").onclick = () => done(false);
    });
}

const fmtTime = ts => new Date(ts * 1000).toLocaleString();

function ago(ts) {
    const s = Math.max(0, Date.now() / 1000 - ts);
    if (s < 90) return "just now";
    if (s < 3600) return `${Math.round(s / 60)} min ago`;
    if (s < 86400 * 2) return `${Math.round(s / 3600)} h ago`;
    return `${Math.round(s / 86400)} days ago`;
}

const sessionGet = k => { try { return sessionStorage.getItem(k); } catch (e) { return null; } };
const sessionSet = (k, v) => { try { sessionStorage.setItem(k, v); } catch (e) { /* ignore */ } };

/* ------------------------------------------------------------ fix options
 * Flatten an issue's fixes into choosable options. Booleans with several
 * candidates become one option each.
 */

const FIX_TEXT = {
    restorecon: "The file's SELinux label doesn't match where it lives, usually because it was " +
        "moved with <code>mv</code> or created somewhere else. Putting back the default label is " +
        "the safest fix: no policy changes.",
    boolean: "The SELinux policy already has a switch (a <em>boolean</em>) for this kind of " +
        "access. Turning it on allows it for this program without writing new policy.",
    fcontext: "The program is fine, but its data lives in a custom location (not where the policy " +
        "expects it), so the files got a generic label. This adds a labeling rule for that directory " +
        "and applies it. Files created there later get the right label too.",
    port: "The program is configured to use a port SELinux doesn't associate with it. Labeling " +
        "the port tells SELinux it belongs to this kind of service. Restart the service afterwards.",
    relabel: "These files have no SELinux label at all, typically because the disk was used " +
        "while SELinux was off. A full relabel at the next boot fixes all of them. Booting will " +
        "take longer once.",
    module: "No label fix or switch covers this. You can add a small local policy module that " +
        "allows exactly the rule below. Only do this if you trust the program and expect it to " +
        "do this: it widens what the program is allowed to do. You can remove the module later " +
        "from the History tab.",
};

const WHY_TEXT = {
    constraint: "This was blocked by a policy <em>constraint</em> (for example different SELinux " +
        "users or MLS levels), which local modules can't override. It usually means the process " +
        "or file runs with the wrong SELinux user or role.",
    role: "The SELinux role of the process isn't allowed to use this type. Check which role the " +
        "user logs in with (<code>semanage login -l</code>).",
    dontaudit: "The policy normally hides this denial. It's usually harmless.",
    allowed: "The currently loaded policy already allows this, so it was fixed after it was logged.",
    label_ok_now: "When this was logged the target had no label, but it is correctly labeled now. " +
        "This often happens early at boot, before a filesystem gets its labels. There is nothing to " +
        "fix; if it comes back after every boot and something doesn't work, report it as a bug.",
};

// Where openSUSE wants SELinux bugs filed, by distribution (bugzilla.opensuse.org products)
function bugzilla(st) {
    const id = (st && st.os_id) || "", ver = (st && st.os_version) || "";
    const name = (st && st.os) || "";
    let product = "openSUSE Tumbleweed", version = "Current", label = "Tumbleweed";
    if (id === "opensuse-leap") {
        product = "openSUSE Distribution"; version = "Leap " + ver; label = "Leap " + ver;
    } else if (id === "opensuse-leap-micro") {
        product = "openSUSE Leap Micro"; version = ver; label = "Leap Micro " + ver;
    } else if (/kalpa/i.test(name) || /kalpa/i.test((st && st.os_variant) || "")) {
        product = "openSUSE Kalpa"; label = "Kalpa";
    } else if (/slowroll/i.test(name)) {
        version = "Slowroll"; label = "Tumbleweed (Slowroll)";
    }
    // Aeon, MicroOS and plain Tumbleweed are all filed under Tumbleweed
    const q = new URLSearchParams({ product, component: "SELinux", version });
    return { url: "https://bugzilla.opensuse.org/enter_bug.cgi?" + q.toString(), label };
}

const REPORT_HTML = {
    label_ok_now: st => {
        const b = bugzilla(st);
        return `<p class="report">Report it to openSUSE:
        <a href="${esc(b.url)}" target="_blank" rel="noopener">openSUSE Bugzilla → ${esc(b.label)}</a>.
        Mention the <code>selinux-policy</code> package and paste the log entry below.</p>`;
    },
};

function fixOptions(issue) {
    const opts = [];
    for (const f of issue.fixes || []) {
        if (f.type === "boolean") {
            for (const o of f.options) {
                const on = o.value === 1;
                opts.push({
                    type: "boolean",
                    label: `${on ? "Turn on" : "Turn off"} boolean ${o.name}`,
                    desc: (o.description ? o.description + ". " : "") +
                          (o.current === null ? "" : `Currently ${o.current ? "on" : "off"}.`),
                    commands: [`setsebool -P ${o.name} ${o.value}`],
                    payload: { type: "boolean", name: o.name, value: o.value },
                    undoable: true,
                });
            }
        } else if (f.type === "restorecon") {
            opts.push({
                type: "restorecon", label: f.title,
                desc: f.paths.map(p => `${p.path}: ${p.from} → ${p.to}`).join("\n"),
                commands: f.commands, payload: { type: "restorecon", paths: f.paths.map(p => p.path) },
            });
        } else if (f.type === "fcontext") {
            opts.push({
                type: "fcontext", label: f.title, undoable: true,
                desc: `${f.dir}: ${f.was} → ${f.setype}` + (f.note ? `\n${f.note}` : ""),
                commands: f.commands, payload: { type: "fcontext", dir: f.dir, setype: f.setype },
            });
        } else if (f.type === "port") {
            opts.push({
                type: "port", label: f.title, undoable: true,
                desc: f.ports.map(p => `${p.port}/${p.proto}: ${p.was} → ${p.type}`).join("\n"),
                commands: f.commands, payload: { type: "port", ports: f.ports.map(({ port, proto, type }) => ({ port, proto, type })) },
            });
        } else if (f.type === "relabel") {
            opts.push({ type: "relabel", label: f.title, desc: "Needs a reboot.",
                        commands: f.commands, payload: { type: "relabel" } });
        } else if (f.type === "module") {
            opts.push({
                type: "module", label: f.title, desc: `Module name: ${f.name}`,
                commands: f.commands, te: f.te, risky: true, undoable: true,
                payload: { type: "module", name: f.name, te: f.te },
            });
        }
    }
    return opts;
}

/* ------------------------------------------------------------------ scan */

async function scan({ prompt = false } = {}) {
    if (scanning) return;
    scanning = true;
    $("#scan").disabled = true;
    $("#review").disabled = true;
    if (!result) $("#body").innerHTML = `<div class="loading">Reading the logs…</div>`;
    else $("#scan").textContent = "Scanning…";
    try {
        result = await helper(["scan", "--hours", $("#range").value]);
        render();
        if (prompt) maybePrompt();
    } catch (ex) {
        showAlert("Could not read the logs: " + errText(ex));
        if (!result) $("#body").innerHTML = "";
    } finally {
        scanning = false;
        $("#scan").disabled = false;
        $("#scan").textContent = "Scan again";
    }
}

const isOpen = i => i.state === "open" || i.state === "recurred";
const openIssues = () => (result?.issues || []).filter(isOpen);

function maybePrompt() {
    const st = result.status;
    const open = openIssues();
    if (!st.enabled || !open.length || sessionGet(PROMPTED)) return;
    sessionSet(PROMPTED, "1");
    const fixable = open.filter(i => i.fixable).length;
    const blocked = open.filter(i => i.blocked).length;
    $("#prompt-title").textContent = `${open.length} SELinux problem${open.length === 1 ? "" : "s"} found`;
    $("#prompt-text").innerHTML =
        `SELinux denied something ${open.reduce((n, i) => n + i.count, 0)} times in the selected period` +
        (blocked ? `, and <strong>${blocked}</strong> of these problems actually blocked a program` : "") +
        `. ${fixable ? `A fix is available for <strong>${fixable}</strong>.` : "None can be fixed automatically."}` +
        `<br><br>Would you like to review them and correct the issues now? Nothing is changed ` +
        `until you approve each fix.` +
        (st.root ? "" : `<br><br><span class="warn-text">You have limited access. Turn on administrative ` +
                        `access at the top of Cockpit to apply fixes.</span>`);
    $("#prompt-ok").textContent = fixable ? "Review and fix" : "Review";
    $("#prompt").hidden = false;
    $("#prompt-ok").onclick = () => { $("#prompt").hidden = true; startWizard(open); };
    $("#prompt-later").onclick = () => { $("#prompt").hidden = true; };
}

/* ---------------------------------------------------------------- render */

function render() {
    const st = result.status;
    const issues = result.issues;
    const open = issues.filter(isOpen);
    const counts = {
        open: open.length,
        fixed: issues.filter(i => i.state === "fixed").length,
        ignored: issues.filter(i => i.state === "ignored").length,
    };
    for (const k in counts) $("#n-" + k).textContent = counts[k] ? counts[k] : "";
    $("#review").disabled = !open.length || !st.enabled;
    $("#review").textContent = open.length ? `Review & fix (${open.length})` : "Review & fix";

    renderBanners(st);

    const modeClass = { enforcing: "ok-text", permissive: "warn-text" }[st.mode] || "danger-text";
    $("#summary").innerHTML = `
        <div class="stat"><b class="${modeClass}">${esc(st.mode[0].toUpperCase() + st.mode.slice(1))}</b><span>SELinux mode</span></div>
        <div class="stat"><b>${esc(st.policy || "–")}</b><span>Policy</span></div>
        <div class="stat"><b class="${open.some(i => i.blocked) ? "danger-text" : ""}">${open.filter(i => i.blocked).length}</b><span>Blocking problems</span></div>
        <div class="stat"><b>${open.length}</b><span>Open problems</span></div>
        <div class="stat"><b>${counts.fixed}</b><span>Fixed</span></div>
        <div class="stat"><b class="small-b">${esc(result.sources.join(" + ") || "none")}</b><span>Read from · ${esc(ago(result.scanned_at))}</span></div>`;

    renderTab();
}

function renderBanners(st) {
    const b = [];
    if (!st.enabled) {
        const other = st.other_lsm.length ? ` This system uses <strong>${esc(st.other_lsm.join(", "))}</strong> instead.` : "";
        const cfgOn = st.config_mode === "enforcing" || st.config_mode === "permissive";
        const bootOff = st.cmdline_security !== null && st.cmdline_security !== "selinux";
        const why = cfgOn && bootOff
            ? `<p><code>/etc/selinux/config</code> says <strong>${esc(st.config_mode)}</strong>, but the kernel was started with
               <code>security=${esc(st.cmdline_security)}</code>, which turns SELinux off. To turn it on, change that to
               <code>security=selinux selinux=1</code> in <code>GRUB_CMDLINE_LINUX_DEFAULT</code> in <code>/etc/default/grub</code>,
               ${st.transactional
                   ? "then run <code>transactional-update grub.cfg</code>, <code>touch /etc/selinux/.autorelabel</code> and reboot."
                   : "then run <code>grub2-mkconfig -o /boot/grub2/grub.cfg</code>, <code>touch /.autorelabel</code> and reboot."}</p>`
            : "";
        b.push(`<div class="card notice">
            <h2>SELinux is not active on this machine</h2>
            <p>The kernel is running without SELinux, so there are no denials to fix.${other}
            New Tumbleweed installations use SELinux by default; older ones that were installed with
            AppArmor can be switched over. See the
            <a href="https://en.opensuse.org/Portal:SELinux" target="_blank" rel="noopener">openSUSE SELinux portal</a>.</p>
            ${why}
            ${result.issues.length ? `<p class="muted small">The ${result.issues.length} entries below were found in older logs.</p>` : ""}
        </div>`);
    } else if (st.mode === "permissive") {
        b.push(`<div class="alert warning"><span>SELinux is in <strong>permissive</strong> mode: denials are
            logged but nothing is blocked. Fix the problems below before switching to enforcing.</span></div>`);
    }
    if (st.enabled && st.missing_packages.length) {
        b.push(`<div class="alert warning"><span>Some troubleshooting tools are missing, so fewer fixes can
            be suggested: <code>${esc(st.missing_packages.join(" "))}</code></span>
            <button id="install-tools" class="btn">Install</button></div>`);
    }
    if (!st.root) {
        b.push(`<div class="alert warning"><span>You have limited access. Some denials (the audit log) can't be
            read and no fixes can be applied. Turn on administrative access at the top of Cockpit.</span></div>`);
    }
    for (const e of result.errors) b.push(`<div class="alert warning"><span>${esc(e)}</span></div>`);
    $("#banners").innerHTML = b.join("");
    const btn = $("#install-tools");
    if (btn) btn.onclick = installTools;
}

function badges(i) {
    const out = [];
    if (i.kind === "error") out.push(`<span class="badge danger">SELinux error</span>`);
    else if (i.blocked) out.push(`<span class="badge danger">Blocked</span>`);
    else out.push(`<span class="badge warn">Logged only (permissive)</span>`);
    if (i.state === "recurred") out.push(`<span class="badge danger">Came back after fix</span>`);
    if (i.state === "fixed") out.push(`<span class="badge ok">Fixed</span>`);
    if (i.state === "ignored") out.push(`<span class="badge">Ignored</span>`);
    if (isOpen(i)) out.push(i.fixable ? `<span class="badge ok">Fix available</span>`
                                      : `<span class="badge">No automatic fix</span>`);
    return out.join(" ");
}

function issueTitle(i) {
    if (i.kind === "error") return "SELinux policy error";
    const target = i.paths[0] || i.names[0] || i.target_type;
    return `<code>${esc(i.comm || i.source_type)}</code> was denied
            <strong>${esc(i.perms.join(", "))}</strong> on ${esc(i.tclass)} <code>${esc(target)}</code>`;
}

function issueMeta(i) {
    if (i.kind === "error") return esc(i.message);
    return `Process type <code>${esc(i.source_type)}</code> → target type <code>${esc(i.target_type)}</code>` +
           (i.exe ? ` · ${esc(i.exe)}` : "");
}

function renderTab() {
    $$(".tabs [role=tab]").forEach(b => b.setAttribute("aria-selected", String(b.dataset.tab === currentTab)));
    const body = $("#body");
    if (currentTab === "history") return renderHistory(body);

    const list = result.issues.filter(i => currentTab === "open" ? isOpen(i) : i.state === currentTab);
    if (!list.length) {
        const msg = {
            open: result.status.enabled
                ? "No SELinux problems in the selected period. 🎉"
                : "No SELinux denials found.",
            fixed: "Nothing fixed in the selected period yet.",
            ignored: "You are not ignoring any problems.",
        }[currentTab];
        body.innerHTML = `<div class="card empty muted">${msg}</div>`;
        return;
    }
    body.innerHTML = list.map(i => `
        <article class="card issue" data-id="${esc(i.id)}">
            <div class="issue-head">
                <div class="issue-title">${issueTitle(i)}</div>
                <div class="issue-badges">${badges(i)}</div>
            </div>
            <div class="muted small">${issueMeta(i)}</div>
            <div class="muted small">${i.count}× · first ${esc(fmtTime(i.first))} · last ${esc(ago(i.last))}
                ${i.fix_applied ? ` · fix applied ${esc(ago(i.fix_applied.at))} (${esc(i.fix_applied.type)})` : ""}</div>
            <details>
                <summary>Details</summary>
                ${i.why_text ? `<h3>audit2why</h3><pre class="log">${esc(i.why_text)}</pre>` : ""}
                ${(i.fixes || []).map(f => `<h3>${esc(f.title)}</h3><pre class="log">${esc(f.commands.join("\n"))}</pre>`).join("")}
                <h3>Log entries${i.lines.length < i.count ? ` (first ${i.lines.length})` : ""}</h3>
                <pre class="log">${esc(i.lines.join("\n"))}</pre>
            </details>
            <div class="issue-actions">
                ${isOpen(i) && result.status.enabled ? `<button class="btn primary" data-act="review">${i.fixable ? "Fix…" : "Review…"}</button>` : ""}
                ${i.state === "ignored" ? `<button class="btn" data-act="unignore">Stop ignoring</button>`
                                        : isOpen(i) ? `<button class="btn" data-act="ignore">Ignore</button>` : ""}
                ${i.state === "fixed" && i.fix_applied && UNDOABLE.includes(i.fix_applied.type)
                    ? `<button class="btn danger-outline" data-act="undo">Undo fix</button>` : ""}
            </div>
        </article>`).join("");

    $$(".issue [data-act]", body).forEach(btn => {
        btn.onclick = () => {
            const issue = result.issues.find(i => i.id === btn.closest(".issue").dataset.id);
            ({ review: () => startWizard([issue]), ignore: () => ignoreIssue(issue, true),
               unignore: () => ignoreIssue(issue, false), undo: () => undoFix(issue.id, issue.summary) })[btn.dataset.act]();
        };
    });
}

function renderHistory(body) {
    const h = (result.history || []).slice().reverse();
    if (!h.length) {
        body.innerHTML = `<div class="card empty muted">No fixes have been applied with SELinux Fixer yet.</div>`;
        return;
    }
    const what = e => ({
        boolean: d => `Set boolean <code>${esc(d.name)}</code> ${d.old} → ${d.new}`,
        module: d => `Installed policy module <code>${esc(d.name)}</code>`,
        restorecon: d => `Restored labels: ${(d.paths || []).map(p => `<code>${esc(p)}</code>`).join(", ")}`,
        relabel: () => "Scheduled full relabel at next boot",
        port: d => `Labeled port ${(d.ports || []).map(p => `<code>${p.port}/${esc(p.proto)}</code> as <code>${esc(p.type)}</code>`).join(", ")}`,
        fcontext: d => `Labeled <code>${esc(d.dir)}</code> as <code>${esc(d.setype)}</code>`,
    }[e.type] || (() => esc(e.type)))(e.detail || {});
    body.innerHTML = `<div class="card list">${h.map((e, n) => `
        <div class="row">
            <div class="row-info">
                <span>${what(e)}</span>
                <span class="muted small">${esc(fmtTime(e.at))} · ${esc(e.summary)}</span>
            </div>
            <div>${e.undone ? `<span class="badge">Undone</span>`
                : UNDOABLE.includes(e.type) ? `<button class="btn danger-outline" data-n="${n}">Undo</button>` : ""}</div>
        </div>`).join("")}</div>`;
    $$("[data-n]", body).forEach(btn => {
        const e = h[+btn.dataset.n];
        btn.onclick = () => undoFix(e.id, e.summary);
    });
}

/* --------------------------------------------------------------- actions */

async function ignoreIssue(issue, on) {
    try {
        await helper([on ? "ignore" : "unignore", issue.id], { input: issue.summary || "", superuser: "require" });
        await scan();
    } catch (ex) {
        showAlert(errText(ex));
    }
}

async function undoFix(id, summary) {
    if (!await confirmDialog("Undo this fix?", `${summary}\n\nThe SELinux change will be reverted and the problem may come back.`, "Undo"))
        return;
    try {
        const r = await helper(["undo", id], { superuser: "require" });
        showAlert(r.log, "success");
        await scan();
    } catch (ex) {
        showAlert(errText(ex));
    }
}

async function installTools() {
    const btn = $("#install-tools");
    btn.disabled = true;
    btn.textContent = "Installing…";
    try {
        const r = await helper(["install-tools"], { superuser: "require" });
        showAlert(r.reboot ? "Tools installed into a new system snapshot. Reboot to start using them."
                           : "Tools installed.", r.reboot ? "warning" : "success");
        await scan();
    } catch (ex) {
        showAlert("Install failed: " + errText(ex));
        btn.disabled = false;
        btn.textContent = "Install";
    }
}

/* ---------------------------------------------------------------- wizard */

const wiz = { queue: [], pos: 0, applied: 0, skipped: 0, ignored: 0, reboot: false, busy: false, done: false };

function startWizard(issues) {
    Object.assign(wiz, { queue: issues, pos: 0, applied: 0, skipped: 0, ignored: 0, reboot: false, busy: false });
    $("#wizard").hidden = false;
    showStep();
}

function closeWizard() {
    if (wiz.busy) return;
    $("#wizard").hidden = true;
    if (wiz.applied || wiz.ignored) scan();
}

function showStep() {
    wiz.done = false;
    if (wiz.pos >= wiz.queue.length) return showSummary();
    const i = wiz.queue[wiz.pos];
    const opts = fixOptions(i);
    $("#wiz-step").textContent = wiz.queue.length > 1 ? `Problem ${wiz.pos + 1} of ${wiz.queue.length}` : "";
    $("#wiz-title").innerHTML = issueTitle(i);
    $("#wiz-ignore").hidden = false;
    $("#wiz-skip").hidden = false;
    $("#wiz-skip").textContent = wiz.queue.length > 1 ? "Skip" : "Cancel";
    $("#wiz-apply").hidden = !opts.length;
    $("#wiz-apply").textContent = "Apply fix";
    $("#wiz-apply").disabled = false;

    let html = `<p class="badges-row">${badges(i)}</p>
        <p class="muted small">${issueMeta(i)}<br>${i.count}× · last ${esc(ago(i.last))}</p>`;
    if (i.state === "recurred")
        html += `<div class="alert warning"><span>A <strong>${esc(i.fix_applied.type)}</strong> fix was applied
                 ${esc(ago(i.fix_applied.at))}, but the denial happened again afterwards.</span></div>`;

    if (opts.length) {
        html += `<h3>${opts.length > 1 ? "Choose a fix" : "Suggested fix"}</h3><div class="fix-list">` +
            opts.map((o, n) => `
            <label class="fix-opt ${o.risky ? "risky" : ""}">
                <input type="radio" name="fix" value="${n}" ${n === 0 ? "checked" : ""}>
                <span class="fix-main">
                    <span class="fix-label"><strong>${esc(o.label)}</strong>
                        ${n === 0 && opts.length > 1 && !o.risky ? `<span class="badge ok">Recommended</span>` : ""}
                        ${o.risky ? `<span class="badge warn">Changes policy</span>` : ""}</span>
                    <span class="fix-desc">${FIX_TEXT[o.type]}</span>
                    ${o.desc ? `<span class="muted small pre">${esc(o.desc)}</span>` : ""}
                </span>
            </label>`).join("") + `</div>
            <div id="fix-detail"></div>`;
    } else {
        html += `<h3>${i.why === "label_ok_now" ? "Nothing to fix" : "No automatic fix"}</h3><p>${WHY_TEXT[i.why] ||
            "SELinux Fixer couldn't find a safe fix for this denial."}</p>`;
        if (i.kind === "error") html += `<pre class="log">${esc(i.message)}</pre>`;
        if (REPORT_HTML[i.why])
            html += REPORT_HTML[i.why](result && result.status) +
                `<details class="report-log"><summary>Log entry for the bug report</summary>
                 <pre class="log">${esc(i.lines.join("\n"))}</pre></details>`;
    }
    if (i.maybe_mislabeled)
        html += `<p class="hint">The target has the generic label <code>${esc(i.target_type)}</code>. If
            the file <code>${esc(i.names[0] || "")}</code> was moved into place with <code>mv</code>, running
            <code>restorecon -Rv</code> on its directory usually fixes this.</p>`;
    html += `<div id="wiz-result"></div>`;
    $("#wiz-body").innerHTML = html;

    const update = () => {
        const sel = $("input[name=fix]:checked", $("#wiz-body"));
        if (!sel) return;
        const o = opts[+sel.value];
        $("#fix-detail").innerHTML =
            (o.te ? `<h3>Policy that will be installed</h3><pre class="log">${esc(o.te)}</pre>
                     <label class="ack"><input type="checkbox" id="ack"> I've read this rule and trust
                     <code>${esc(i.comm || i.source_type)}</code> to do this.</label>` : "") +
            `<h3>Commands</h3><pre class="log">${esc(o.commands.join("\n"))}</pre>`;
        const ack = $("#ack");
        $("#wiz-apply").disabled = !!ack;
        if (ack) ack.onchange = () => { $("#wiz-apply").disabled = !ack.checked; };
    };
    $$("input[name=fix]", $("#wiz-body")).forEach(r => { r.onchange = update; });
    update();

    $("#wiz-apply").onclick = () => applyCurrent(i, opts);
    $("#wiz-skip").onclick = () => {
        if (wiz.queue.length === 1 && !wiz.done) return closeWizard();
        wiz.skipped++; wiz.pos++; showStep();
    };
    $("#wiz-ignore").onclick = async () => {
        try {
            await helper(["ignore", i.id], { input: i.summary || "", superuser: "require" });
            wiz.ignored++; wiz.pos++; showStep();
        } catch (ex) {
            $("#wiz-result").innerHTML = `<div class="alert danger"><span>${esc(errText(ex))}</span></div>`;
        }
    };
}

async function applyCurrent(issue, opts) {
    if (wiz.done) { wiz.pos++; return showStep(); }
    const o = opts[+$("input[name=fix]:checked", $("#wiz-body")).value];
    wiz.busy = true;
    $$("#wizard .modal-actions button").forEach(b => { b.disabled = true; });
    $$("input", $("#wiz-body")).forEach(x => { x.disabled = true; });
    $("#wiz-result").innerHTML = `<div class="loading">Applying…</div>`;
    try {
        const r = await helper(["apply"], {
            superuser: "require",
            input: JSON.stringify({ id: issue.id, summary: issue.summary, fix: o.payload, lines: issue.lines }),
        });
        wiz.applied++;
        if (r.reboot) wiz.reboot = true;
        $("#wiz-result").innerHTML = `<div class="alert success"><span>Fix applied.</span></div>
            <pre class="log">${esc(r.log)}</pre>`;
        wiz.done = true;
        $("#wiz-ignore").hidden = true;
        $("#wiz-skip").hidden = true;
        $("#wiz-apply").textContent = wiz.pos + 1 < wiz.queue.length ? "Next problem" : "Finish";
    } catch (ex) {
        $("#wiz-result").innerHTML = `<div class="alert danger"><span>The fix failed: ${esc(errText(ex))}</span></div>`;
        $$("input", $("#wiz-body")).forEach(x => { x.disabled = false; });
    } finally {
        wiz.busy = false;
        $$("#wizard .modal-actions button").forEach(b => { b.disabled = false; });
        const ack = $("#ack");
        if (ack && !wiz.done) $("#wiz-apply").disabled = !ack.checked;
    }
}

function showSummary() {
    if (wiz.queue.length === 1) return closeWizard();
    $("#wiz-step").textContent = "";
    $("#wiz-title").textContent = "Review finished";
    const parts = [`<strong>${wiz.applied}</strong> fixed`, `<strong>${wiz.skipped}</strong> skipped`,
                   `<strong>${wiz.ignored}</strong> ignored`];
    $("#wiz-body").innerHTML = `<p>${parts.join(" · ")}</p>` +
        (wiz.applied ? `<p class="muted">If a program was failing because of these denials, restart it. Problems
            that happen again after a fix show up as <em>Came back after fix</em>.</p>` : "") +
        (wiz.reboot ? `<div class="alert warning"><span>A full relabel is scheduled. Reboot the machine to run it.</span></div>` : "");
    $("#wiz-ignore").hidden = true;
    $("#wiz-skip").hidden = true;
    $("#wiz-apply").hidden = false;
    $("#wiz-apply").disabled = false;
    $("#wiz-apply").textContent = "Close";
    $("#wiz-apply").onclick = closeWizard;
}

/* ------------------------------------------------------------------ init */

$$(".tabs [role=tab]").forEach(b => {
    b.onclick = () => { currentTab = b.dataset.tab; if (result) renderTab(); };
});
$("#scan").onclick = () => scan();
$("#range").onchange = () => scan();
$("#review").onclick = () => startWizard(openIssues());
$("#wiz-close").onclick = closeWizard;
document.addEventListener("keydown", e => {
    if (e.key !== "Escape") return;
    if (!$("#wizard").hidden) closeWizard();
    $("#prompt").hidden = true;
});

cockpit.transport.wait(() => {
    $("#host").textContent = cockpit.transport.host === "localhost"
        ? (window.location.hostname || "this machine") : cockpit.transport.host;
    cockpit.file("/etc/hostname").read().then(h => { if (h?.trim()) $("#host").textContent = h.trim(); }).catch(() => {});

    // Rescan when the user switches between limited and administrative access.
    const su = cockpit.dbus(null, { bus: "internal" }).proxy("cockpit.Superuser", "/superuser");
    let lastSu;
    su.addEventListener("changed", () => {
        if (lastSu !== undefined && su.Current !== lastSu) scan({ prompt: true });
        lastSu = su.Current;
    });

    scan({ prompt: true });
});
