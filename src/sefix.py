#!/usr/bin/python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""
selinux-fixer — find SELinux denials in the logs of an openSUSE
(Tumbleweed, Leap 16, Kalpa/Aeon/MicroOS) machine, explain them, and fix them on request.

The Cockpit page runs this same file (fetched from the package directory and
executed with `python3 -c`). It also works on its own from a shell:

    sudo selinux-fixer review            # walk through problems, asks before each fix
    sudo selinux-fixer list --hours 24   # plain-text summary
    sudo selinux-fixer scan              # JSON (what the Cockpit page reads)

Subcommands
    status              SELinux mode, policy, which tools are installed (JSON)
    scan                find and analyse denials (JSON)
    list                same as scan, as readable text
    review              interactive: show each open problem, ask whether to fix it
    apply               apply one fix; JSON request on stdin
    undo  ID            revert the last fix for issue ID (booleans, modules)
    ignore ID / unignore ID
    install-tools       zypper install the SELinux troubleshooting tools

Denials are read from the audit log (ausearch, when auditd runs) and from the
systemd journal (audit and kernel messages), so they are found whether or not
auditd is installed. Fixes are tried in this order:

    1. restorecon     the file has the wrong label; restore the default one
    2. boolean        the policy has a switch for this; turn it on/off
    3. relabel        unlabeled files; relabel the filesystem at next boot
    4. module         last resort: a local policy module built by audit2allow
"""

import argparse
import datetime
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time

STATE_DIR = "/var/lib/cockpit-selinux-fixer"
STATE_FILE = os.path.join(STATE_DIR, "state.json")
MODULE_DIR = os.path.join(STATE_DIR, "modules")
MODULE_PREFIX = "sefix_"
MAX_LINES_PER_ISSUE = 40

# command -> openSUSE package
TOOLS = {
    "ausearch": "audit",
    "audit2why": "policycoreutils-python-utils",
    "audit2allow": "policycoreutils-python-utils",
    "semanage": "policycoreutils-python-utils",
    "restorecon": "policycoreutils",
    "setsebool": "policycoreutils",
    "semodule": "policycoreutils",
    "semodule_package": "policycoreutils",
    "checkmodule": "checkpolicy",
}
# Not all of these are needed for every fix; these are the ones without which
# the page can't do anything useful beyond listing denials.
ESSENTIAL = ["audit2why", "audit2allow", "restorecon", "setsebool", "semodule", "checkmodule"]

# Target types that mean "this object has no proper label".
UNLABELED_TYPES = {"unlabeled_t", "file_t"}
# Target types that usually mean "file was created/copied in the wrong place
# or moved with mv" — a restorecon candidate even when we can't see the path.
GENERIC_TYPES = {"default_t", "user_home_t", "user_tmp_t", "tmp_t", "var_t", "etc_t",
                 "admin_home_t", "user_home_dir_t", "usr_t", "mnt_t", "home_root_t"}

AUDIT_TYPES = {"AVC", "USER_AVC", "SELINUX_ERR", "USER_SELINUX_ERR", "PATH", "CWD", "SYSCALL"}
AUDIT_NUM = {"1400": "AVC", "1107": "USER_AVC", "1401": "SELINUX_ERR",
             "1122": "USER_SELINUX_ERR", "1302": "PATH", "1307": "CWD", "1300": "SYSCALL"}

RE_STAMP = re.compile(r"audit\((\d+(?:\.\d+)?):(\d+)\)")
RE_TYPE = re.compile(r"\btype=(\w+)")
RE_AVC = re.compile(r"avc:\s+(denied|granted)\s+\{\s*([^}]*?)\s*\}\s+for\s+(.*)")
RE_KV = re.compile(r"(\w+)=(\"[^\"]*\"|'[^']*'|\S+)")
RE_HEX = re.compile(r"^[0-9A-Fa-f]+$")


# ------------------------------------------------------------------- utils

def which(cmd):
    return shutil.which(cmd, path=os.environ.get("PATH", "") + ":/usr/sbin:/sbin")


def run(argv, input=None, cwd=None, check=False, timeout=300):
    exe = which(argv[0])
    if not exe:
        raise FileNotFoundError(f"{argv[0]} is not installed")
    # Never pass our stdin on: some tools (ausearch) read from it when it is
    # not a terminal and would wait forever.
    extra = {} if input is not None else {"stdin": subprocess.DEVNULL}
    try:
        p = subprocess.run([exe] + argv[1:], input=input, cwd=cwd, text=True, timeout=timeout,
                           capture_output=True, env={**os.environ, "LC_ALL": "C"}, **extra)
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"{argv[0]} did not finish within {timeout} seconds")
    if check and p.returncode != 0:
        msg = (p.stderr or p.stdout).strip() or f"exit code {p.returncode}"
        raise RuntimeError(f"{' '.join(argv)}: {msg}")
    return p


def read_text(path, default=None):
    try:
        with open(path) as f:
            return f.read()
    except OSError:
        return default


# Only these string fields are hex-encoded by audit when they contain odd
# characters; numbers (ino, src, pid) must never be decoded.
HEX_FIELDS = {"name", "path", "comm", "exe", "cmdline", "proctitle", "cwd", "dir"}


def unhex(v, key=None):
    """Audit writes strings with odd characters as bare hex instead of "quoted"."""
    if v.startswith('"') and v.endswith('"'):
        return v[1:-1]
    if v.startswith("'") and v.endswith("'"):
        return v[1:-1]
    if key in HEX_FIELDS and RE_HEX.match(v) and len(v) % 2 == 0 and len(v) >= 2:
        try:
            s = bytes.fromhex(v).decode("utf-8")
            if s.isprintable():
                return s
        except ValueError:
            pass
    return v


def ctx_type(ctx):
    parts = (ctx or "").split(":")
    return parts[2] if len(parts) >= 3 else ctx or ""


def emit(obj):
    json.dump(obj, sys.stdout, indent=1)
    sys.stdout.write("\n")


# ------------------------------------------------------------------- state

def load_state():
    try:
        with open(STATE_FILE) as f:
            s = json.load(f)
    except (OSError, ValueError):
        s = {}
    s.setdefault("fixed", {})
    s.setdefault("ignored", {})
    s.setdefault("history", [])
    return s


def save_state(s):
    os.makedirs(STATE_DIR, mode=0o755, exist_ok=True)
    s["history"] = s["history"][-200:]
    tmp = STATE_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(s, f, indent=1)
    os.replace(tmp, STATE_FILE)


# ------------------------------------------------------------------ status

def read_only(path):
    try:
        return bool(os.statvfs(path).f_flag & os.ST_RDONLY)
    except OSError:
        return False


def is_transactional():
    """Kalpa, Aeon, MicroOS, Leap Micro: read-only root, changes via transactional-update."""
    return read_only("/") and bool(which("transactional-update"))


def autorelabel_flag():
    # MicroOS-style systems (selinux-autorelabel) look in /etc/selinux; / may be read-only
    if is_transactional() or os.path.exists("/usr/lib/systemd/system-generators/selinux-autorelabel-generator"):
        return "/etc/selinux/.autorelabel"
    return "/.autorelabel"


def selinux_status():
    lsm = (read_text("/sys/kernel/security/lsm", "") or "").strip().split(",")
    enforce = read_text("/sys/fs/selinux/enforce")
    cfg = read_text("/etc/selinux/config", "") or ""
    conf = dict(re.findall(r"^\s*(SELINUX|SELINUXTYPE)\s*=\s*(\S+)", cfg, re.M))
    enabled = enforce is not None
    mode = "disabled"
    if enabled:
        mode = "enforcing" if enforce.strip() == "1" else "permissive"
    tools = {t: which(t) for t in TOOLS}
    missing = sorted({TOOLS[t] for t in ESSENTIAL if not tools[t]} |
                     ({"audit"} if not tools["ausearch"] else set()))
    auditd = subprocess.run(["systemctl", "is-active", "--quiet", "auditd"], stdin=subprocess.DEVNULL,
                            capture_output=True).returncode == 0
    others = [x for x in lsm if x in ("apparmor", "smack", "tomoyo")]
    osr = {}
    for line in (read_text("/etc/os-release", "") or "").splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            osr[k.strip()] = v.strip().strip('"')
    return {
        "os": osr.get("PRETTY_NAME", "Linux"),
        "os_id": osr.get("ID", ""),
        "os_version": osr.get("VERSION_ID", ""),
        "os_variant": osr.get("VARIANT_ID", ""),
        "enabled": enabled,
        "mode": mode,
        "config_mode": conf.get("SELINUX"),
        "policy": conf.get("SELINUXTYPE"),
        "lsm": lsm,
        "other_lsm": others,
        "auditd": auditd,
        "root": os.geteuid() == 0,
        "tools": tools,
        "missing_packages": missing,
        "transactional": is_transactional(),
        "cmdline": (read_text("/proc/cmdline", "") or "").strip(),
        "cmdline_security": (re.findall(r"\bsecurity=(\S*)", read_text("/proc/cmdline", "") or "") or [None])[-1],
    }


# ------------------------------------------------------------------ reading

class Record:
    __slots__ = ("type", "ts", "serial", "body", "raw")

    def __init__(self, rtype, ts, serial, body):
        self.type = rtype
        self.ts = ts
        self.serial = serial
        self.body = body
        # normalised raw form, which audit2allow/audit2why understand
        self.raw = f"type={rtype} msg=audit({ts:.3f}:{serial}): {body}"


def parse_raw_line(line):
    """Parse a line in audit.log / kernel format."""
    m = RE_STAMP.search(line)
    t = RE_TYPE.search(line)
    if not m:
        return None
    rtype = t.group(1) if t else ("AVC" if "avc:" in line else "")
    rtype = AUDIT_NUM.get(rtype, rtype)
    if rtype not in AUDIT_TYPES:
        return None
    body = line[m.end():].lstrip(": ").rstrip("\n")
    return Record(rtype, float(m.group(1)), m.group(2), body)


def read_ausearch(cutoff, errors):
    if not which("ausearch"):
        return []
    try:
        p = run(["ausearch", "--input-logs", "--raw", "-m", "AVC,USER_AVC,SELINUX_ERR,USER_SELINUX_ERR"],
                timeout=120)
    except RuntimeError as ex:
        errors.append(str(ex))
        return []
    if p.returncode not in (0, 1):  # 1 = no matches
        err = p.stderr.strip()
        if err and "<no matches>" not in err:
            errors.append(f"ausearch: {err.splitlines()[-1]}")
        return []
    out = []
    for line in p.stdout.splitlines():
        r = parse_raw_line(line)
        if r and r.ts >= cutoff:
            out.append(r)
    return out


def read_journal(cutoff, errors):
    if not which("journalctl"):
        return []
    argv = ["journalctl", "-o", "json", "--no-pager", "-q", f"--since=@{int(cutoff)}",
            "_TRANSPORT=audit", "+", "_TRANSPORT=kernel"]
    p = run(argv)
    if p.returncode != 0:
        if p.stderr.strip():
            errors.append("journalctl: " + p.stderr.strip().splitlines()[-1])
        return []
    out = []
    for line in p.stdout.splitlines():
        try:
            e = json.loads(line)
        except ValueError:
            continue
        msg = e.get("MESSAGE")
        if isinstance(msg, list):  # binary message, journal gives bytes
            msg = bytes(msg).decode("utf-8", "replace")
        if not isinstance(msg, str):
            continue
        if e.get("_TRANSPORT") == "audit":
            rtype = e.get("_AUDIT_TYPE_NAME") or AUDIT_NUM.get(str(e.get("_AUDIT_TYPE")), "")
            if rtype not in AUDIT_TYPES:
                continue
            m = RE_STAMP.search(msg)
            if m:  # some journald versions keep the audit( ) prefix
                ts, serial, body = float(m.group(1)), m.group(2), msg[m.end():].lstrip(": ")
            else:
                ts = int(e.get("__REALTIME_TIMESTAMP", "0")) / 1e6
                serial, body = str(e.get("_AUDIT_ID", "0")), msg
            out.append(Record(rtype, ts, serial, body))
        elif "audit" in msg and ("avc:" in msg or "type=1302" in msg or "type=1401" in msg):
            r = parse_raw_line(msg)
            if r:
                out.append(r)
    return out


def read_file(path):
    out = []
    with open(path, errors="replace") as f:
        for line in f:
            r = parse_raw_line(line)
            if r:
                out.append(r)
    return out


def collect(cutoff, files=None):
    errors, sources = [], []
    records = []
    if files:
        for fn in files:
            records += read_file(fn)
        sources.append("file")
    else:
        a = read_ausearch(cutoff, errors)
        if a:
            sources.append("audit.log")
        j = read_journal(cutoff, errors)
        if j:
            sources.append("journal")
        records = a + j
    # de-duplicate (same event can be in audit.log and the journal)
    seen, uniq = set(), []
    for r in records:
        k = (int(r.ts), r.serial, r.type, r.body[:120])
        if k not in seen:
            seen.add(k)
            uniq.append(r)
    return uniq, sources, errors


# ----------------------------------------------------------------- grouping

def parse_avc(r):
    body = r.body
    if r.type == "USER_AVC":
        m = re.search(r"msg='(.*?)'?$", body)
        if m:
            body = m.group(1)
    m = RE_AVC.search(body)
    if not m or m.group(1) != "denied":
        return None
    fields = {k: unhex(v, k) for k, v in RE_KV.findall(m.group(3))}
    return {
        "perms": m.group(2).split(),
        "fields": fields,
    }


def short_hash(s):
    return hashlib.sha1(s.encode()).hexdigest()[:10]


def group_records(records):
    paths_by_event = {}
    for r in records:
        if r.type == "PATH":
            f = {k: unhex(v, k) for k, v in RE_KV.findall(r.body)}
            name = f.get("name", "")
            if name.startswith("/"):
                paths_by_event.setdefault((int(r.ts), r.serial), []).append(name)

    groups = {}
    for r in records:
        if r.type in ("SELINUX_ERR", "USER_SELINUX_ERR"):
            key = "err|" + re.sub(r"\b(pid|ses|auid|uid)=\S+", "", r.body)[:200]
            g = groups.setdefault(key, {
                "id": short_hash(key), "kind": "error", "message": r.body,
                "count": 0, "first": r.ts, "last": r.ts, "lines": [],
            })
        elif r.type in ("AVC", "USER_AVC"):
            a = parse_avc(r)
            if not a:
                continue
            f = a["fields"]
            scon, tcon, tclass = f.get("scontext", ""), f.get("tcontext", ""), f.get("tclass", "")
            stype, ttype = ctx_type(scon), ctx_type(tcon)
            # USER_AVC (systemd, dbus) names the requesting command in cmdline
            comm = (f.get("comm") or f.get("cmdline", "").split(" ")[0].rsplit("/", 1)[-1]
                    or f.get("exe", "").rsplit("/", 1)[-1] or "")
            key = f"avc|{stype}|{ttype}|{tclass}|{comm}"
            g = groups.setdefault(key, {
                "id": short_hash(key), "kind": "avc",
                "source_type": stype, "target_type": ttype, "tclass": tclass,
                "scontext": scon, "tcontext": tcon, "comm": comm, "exe": f.get("exe", ""),
                "perms": [], "names": [], "paths": [], "inodes": [], "ports": [],
                "user_avc": r.type == "USER_AVC",
                "blocked": False, "count": 0, "first": r.ts, "last": r.ts, "lines": [],
            })
            for p in a["perms"]:
                if p not in g["perms"]:
                    g["perms"].append(p)
            if f.get("permissive", "0") == "0":
                g["blocked"] = True
            name = f.get("name")
            if f.get("ino") and f.get("dev") and len(g["inodes"]) < 5:
                ref = [f["dev"].strip('"'), int(f["ino"]) if f["ino"].isdigit() else 0, name or ""]
                if ref[1] and ref not in g["inodes"]:
                    g["inodes"].append(ref)
            port = f.get("src") if "name_bind" in a["perms"] else None
            if port and port.isdigit() and int(port) not in g["ports"]:
                g["ports"].append(int(port))
            if name and name not in g["names"] and len(g["names"]) < 20:
                g["names"].append(name)
            cand = []
            if f.get("path", "").startswith("/"):
                cand.append(f["path"])
            for p in paths_by_event.get((int(r.ts), r.serial), []):
                if not name or os.path.basename(p.rstrip("/")) == name or len(cand) == 0:
                    cand.append(p)
            for p in cand:
                if p not in g["paths"] and len(g["paths"]) < 20:
                    g["paths"].append(p)
            if g["exe"] == "" and f.get("exe"):
                g["exe"] = f["exe"]
        else:
            continue
        g["count"] += 1
        g["first"] = min(g["first"], r.ts)
        g["last"] = max(g["last"], r.ts)
        if len(g["lines"]) < MAX_LINES_PER_ISSUE:
            g["lines"].append(r.raw)
    return sorted(groups.values(), key=lambda g: -g["last"])


# ----------------------------------------------------------------- analysis

def audit2why(lines):
    if not which("audit2why") or not lines:
        return None
    p = run(["audit2why"], input="\n".join(lines[:1]) + "\n")
    out = (p.stdout or "") + (p.stderr or "")
    return out.strip() if out.strip() else None


def classify_why(text):
    if not text:
        return "unknown", []
    bools = []
    for name, val in re.findall(r"setsebool\s+-P\s+(\w+)\s+(\d|on|off|true|false)", text):
        v = 1 if val in ("1", "on", "true") else 0
        if (name, v) not in bools:
            bools.append((name, v))
    t = text.lower()
    if bools:
        return "boolean", bools
    if "missing type enforcement" in t:
        return "te", []
    if "constraint violation" in t:
        return "constraint", []
    if "missing role allow" in t:
        return "role", []
    if "would be allowed by active policy" in t or "possible mismatch" in t:
        return "allowed", []
    if "dontaudit" in t:
        return "dontaudit", []
    return "unknown", []


def boolean_value(name):
    v = read_text(f"/sys/fs/selinux/booleans/{name}")
    if v is None:
        return None
    try:
        return int(v.split()[0])
    except (ValueError, IndexError):
        return None


_bool_desc = None


def boolean_descriptions():
    global _bool_desc
    if _bool_desc is None:
        _bool_desc = {}
        if which("semanage"):
            p = run(["semanage", "boolean", "-l", "-n"])
            for line in p.stdout.splitlines():
                m = re.match(r"(\w+)\s+\(\s*\w+\s*,\s*\w+\s*\)\s+(.*)", line)
                if m:
                    _bool_desc[m.group(1)] = m.group(2).strip()
    return _bool_desc


def restorecon_check(paths):
    """Return [{path, from, to, dir}] for paths whose label differs from the policy default."""
    out = []
    if not which("restorecon"):
        return out
    for path in paths:
        if not os.path.lexists(path) or read_only(path):
            continue
        p = run(["restorecon", "-n", "-v", "-F", "--", path])
        m = re.search(r"Would relabel (.+?) from (\S+) to (\S+)", p.stdout)
        if m and ctx_type(m.group(2)) != ctx_type(m.group(3)):
            out.append({"path": path, "from": m.group(2), "to": m.group(3),
                        "dir": os.path.isdir(path) and not os.path.islink(path)})
    return out


def current_type(path):
    try:
        return ctx_type(os.getxattr(path, "security.selinux", follow_symlinks=False)
                        .decode(errors="replace").rstrip("\0"))
    except OSError:
        return None


FILE_CLASSES = ("file", "dir", "lnk_file", "sock_file", "fifo_file", "chr_file", "blk_file")


def mounts_for_dev(dev):
    """Mounts whose source device is `dev` (as written in AVC dev=)."""
    out = []
    for line in (read_text("/proc/self/mountinfo", "") or "").splitlines():
        parts = line.split()
        try:
            sep = parts.index("-")
        except ValueError:
            continue
        root, mnt = parts[3], parts[4].replace("\\040", " ")
        fstype, src = parts[sep + 1], parts[sep + 2]
        if src.startswith("/dev/") and os.path.basename(os.path.realpath(src)) == dev:
            out.append((mnt, fstype, src, root))
    # shortest mount point last, so specific subvolumes are tried first
    return sorted(out, key=lambda m: -len(m[0]))


def resolve_inode(dev, ino, name):
    """Find the path of inode `ino` on device `dev`; AVCs often carry only a basename."""
    found = []
    tried_fs = set()
    for mnt, fstype, src, root in mounts_for_dev(dev):
        cands = []
        try:
            if fstype == "btrfs" and which("btrfs"):
                p = run(["btrfs", "inspect-internal", "inode-resolve", str(ino), mnt], timeout=15)
                cands = p.stdout.splitlines()
            elif fstype.startswith("ext") and which("debugfs"):
                if src in tried_fs:
                    continue
                tried_fs.add(src)
                p = run(["debugfs", "-R", f"ncheck {ino}", src], timeout=20)
                for line in p.stdout.splitlines()[1:]:
                    rel = line.split("\t", 1)[-1].strip()
                    if rel.startswith(root.rstrip("/") + "/") or root == "/":
                        cands.append(mnt.rstrip("/") + "/" + rel[len(root.rstrip("/")):].lstrip("/"))
            else:
                p = run(["find", mnt, "-xdev", "-inum", str(ino)], timeout=20)
                cands = p.stdout.splitlines()
        except (RuntimeError, FileNotFoundError):
            continue
        for c in cands:
            c = os.path.normpath(c.strip())
            try:
                if os.lstat(c).st_ino != ino:
                    continue
            except OSError:
                continue
            if name and os.path.basename(c) != name:
                continue
            if c not in found:
                found.append(c)
        if found:
            break
    return found


def resolve_paths(g):
    if g["paths"] or g["tclass"] not in FILE_CLASSES or os.geteuid() != 0:
        return
    for dev, ino, name in g["inodes"]:
        for p in resolve_inode(dev, ino, name):
            if p not in g["paths"]:
                g["paths"].append(p)
                g.setdefault("paths_resolved", True)


_port_types = None


def port_types():
    global _port_types
    if _port_types is None:
        _port_types = set()
        if which("semanage"):
            for line in run(["semanage", "port", "-l", "-n"]).stdout.splitlines():
                if line.split():
                    _port_types.add(line.split()[0])
    return _port_types


PORT_TYPE_FOR = {"httpd_t": "http_port_t", "sshd_t": "ssh_port_t", "named_t": "dns_port_t",
                 "postfix_master_t": "smtp_port_t", "squid_t": "squid_port_t",
                 "mysqld_t": "mysqld_port_t", "postgresql_t": "postgresql_port_t",
                 "redis_t": "redis_port_t", "dovecot_t": "pop_port_t"}


def bind_allowed(stype, ptype, tclass):
    """True/False if sesearch can tell, None if it isn't installed."""
    if not which("sesearch"):
        return None
    p = run(["sesearch", "-A", "-s", stype, "-t", ptype, "-c", tclass, "-p", "name_bind"])
    return any(l.strip().endswith(";") for l in p.stdout.splitlines())  # unconditional rules only


def port_fix(g):
    if "name_bind" not in g["perms"] or not g["ports"]:
        return None
    proto = {"tcp_socket": "tcp", "udp_socket": "udp", "sctp_socket": "sctp"}.get(g["tclass"])
    if not proto:
        return None
    stype = g["source_type"]
    for ptype in (PORT_TYPE_FOR.get(stype), re.sub(r"_t$", "_port_t", stype)):
        if ptype and ptype in port_types() and bind_allowed(stype, ptype, g["tclass"]) is not False:
            ports = [{"port": p, "proto": proto, "type": ptype, "was": g["target_type"]} for p in g["ports"]]
            return {
                "type": "port", "ports": ports, "port_type": ptype,
                "title": f"Label port {', '.join(str(p['port']) for p in ports)}/{proto} as {ptype}",
                "commands": [f"semanage port -a -t {ptype} -p {proto} {p['port']}" for p in ports],
            }
    return None


# (read type, read/write type) a confined service expects for its data
CONTENT_TYPES = {
    "httpd_t": ("httpd_sys_content_t", "httpd_sys_rw_content_t"),
    "smbd_t": ("samba_share_t", "samba_share_t"),
    "ftpd_t": ("public_content_t", "public_content_rw_t"),
    "nfsd_t": ("public_content_t", "public_content_rw_t"),
    "rsync_t": ("public_content_t", "public_content_rw_t"),
    "named_t": ("named_zone_t", "named_cache_t"),
    "mysqld_t": ("mysqld_db_t", "mysqld_db_t"),
    "postgresql_t": ("postgresql_db_t", "postgresql_db_t"),
    "container_t": ("container_file_t", "container_file_t"),
}
WRITE_PERMS = {"write", "append", "create", "unlink", "rename", "add_name", "remove_name",
               "setattr", "link", "rmdir"}
# Never offer to relabel these wholesale.
PROTECTED_DIRS = {"/", "/bin", "/boot", "/dev", "/etc", "/home", "/lib", "/lib64", "/mnt", "/media",
                  "/opt", "/proc", "/root", "/run", "/sbin", "/srv", "/sys", "/tmp", "/usr",
                  "/usr/local", "/var", "/var/lib", "/var/log", "/var/tmp", "/var/spool"}
PRIVATE_PREFIXES = ("/home/", "/root/", "/tmp/", "/var/tmp/", "/run/user/")
# Services for which sharing a folder from a home directory is normal use.
HOME_SHARING = {"container_t"}


def home_subdir_ok(d):
    """/home/<user>/<something> but not the home itself or hidden dirs like ~/.ssh."""
    parts = d.strip("/").split("/")
    return (len(parts) >= 3 and parts[0] == "home" and
            not any(p.startswith(".") for p in parts[2:]))


def fcontext_fix(g):
    """A service's data lives in a custom location whose default label doesn't fit."""
    types = CONTENT_TYPES.get(g["source_type"])
    if not types or g["tclass"] not in FILE_CLASSES:
        return None
    want = types[1] if WRITE_PERMS & set(g["perms"]) else types[0]
    for path in g["paths"]:
        if not os.path.lexists(path):
            continue
        d = path if (g["tclass"] == "dir" and os.path.isdir(path)) else os.path.dirname(path)
        if d.startswith(PRIVATE_PREFIXES) and not (g["source_type"] in HOME_SHARING and home_subdir_ok(d)):
            continue
        if d in PROTECTED_DIRS or current_type(d) == want or read_only(d):
            continue
        spec = re.escape(d) + "(/.*)?"
        return {
            "type": "fcontext", "dir": d, "spec": spec, "setype": want, "was": g["target_type"],
            "title": f"Label {d} as {want}",
            "note": ("Alternatively, mount the folder with the :z option (podman run -v DIR:/path:z), "
                     "which labels it for you." if g["source_type"] == "container_t" else ""),
            "commands": [f"semanage fcontext -a -t {want} '{spec}'", f"restorecon -R -v -- {d}"],
        }
    return None


def module_name(g):
    base = re.sub(r"[^a-z0-9]+", "_", g["source_type"].lower()).strip("_")
    base = re.sub(r"_t$", "", base)[:30] or "local"
    return f"{MODULE_PREFIX}{base}_{g['id'][:6]}"


def module_preview(g, name):
    if not which("audit2allow"):
        return None
    avc = [l for l in g["lines"] if "avc:" in l]
    p = run(["audit2allow", "-m", name], input="\n".join(avc) + "\n")
    te = p.stdout.strip()
    if p.returncode != 0 or "allow " not in te:
        return None
    return te


def describe(g):
    if g["kind"] == "error":
        return "SELinux reported an error: " + g["message"][:300]
    what = " ".join(g["perms"])
    obj = g["tclass"]
    target = g["names"][0] if g["names"] else (g["paths"][0] if g["paths"] else g["target_type"])
    prog = g["comm"] or g["source_type"]
    return f"{prog} ({g['source_type']}) was denied {what} on {obj} {target} ({g['target_type']})"


def analyse(g, state, deep=True):
    g["summary"] = describe(g)
    g["fixes"] = []
    g["why"] = "unknown"
    g["why_text"] = None
    fx = state["fixed"].get(g["id"])
    if fx and g["last"] <= fx["at"]:
        # fixed and not seen since: no need to work out fixes again
        deep = False
    if g["kind"] == "avc" and deep:
        resolve_paths(g)
        # 1. wrong label on a file we can see
        rel = restorecon_check(g["paths"])
        rel = [r for r in rel if ctx_type(r["from"]) == g["target_type"]] or rel
        if rel:
            g["fixes"].append({
                "type": "restorecon", "paths": rel,
                "title": "Restore the default SELinux label",
                "commands": [" ".join(["restorecon", "-F", "-v"] + (["-R"] if r["dir"] else []) +
                                      ["--", r["path"]]) for r in rel],
            })
        # 1b. right label for the place, but the place is a custom data dir
        fc = None if rel else fcontext_fix(g)
        if fc:
            g["fixes"].append(fc)
        # 1c. service binding a port that has another (or no) label
        pf = port_fix(g)
        if pf:
            g["fixes"].append(pf)
        # 2. policy boolean
        text = audit2why(g["lines"])
        why, bools = classify_why(text)
        g["why"], g["why_text"] = why, text
        if bools and pf:
            bools = []  # e.g. "httpd_enable_ftp_server" for a web server port: the label is better
        if bools:
            desc = boolean_descriptions()
            opts = []
            for name, val in bools:
                cur = boolean_value(name)
                opts.append({"name": name, "value": val, "current": cur,
                             "description": desc.get(name, "")})
            g["fixes"].append({
                "type": "boolean", "options": opts,
                "title": "Turn on an SELinux boolean" if len(opts) == 1 else
                         "Turn on one of these SELinux booleans",
                "commands": [f"setsebool -P {o['name']} {o['value']}" for o in opts],
            })
        # 3. unlabeled objects: but only if they are still unlabeled. Early at
        #    boot, objects can show up as unlabeled_t before they get labeled.
        now = [current_type(p) for p in g["paths"] if os.path.lexists(p)]
        if g["target_type"] in UNLABELED_TYPES and now and \
                all(t and t not in UNLABELED_TYPES for t in now):
            g["why"] = "label_ok_now"
            g["label_now"] = now[0]
        elif g["target_type"] in UNLABELED_TYPES and not rel:
            g["fixes"].append({
                "type": "relabel", "title": "Relabel the whole filesystem at next boot",
                "commands": [f"touch {autorelabel_flag()}", "reboot"],
            })
        # 4. local module, last resort
        # (not when a label is the real cause: a module would just paper over it)
        if not (rel or fc or pf) and g["target_type"] not in UNLABELED_TYPES and why in ("te", "unknown"):
            name = module_name(g)
            te = module_preview(g, name)
            if te:
                g["fixes"].append({
                    "type": "module", "name": name, "te": te,
                    "title": "Allow it with a local policy module",
                    "commands": [f"audit2allow -M {name} < denials.log", f"semodule -i {name}.pp"],
                })
        g["maybe_mislabeled"] = (not (rel or fc) and not g["paths"] and g["target_type"] in GENERIC_TYPES
                                 and g["tclass"] in FILE_CLASSES)
    # state
    fx = state["fixed"].get(g["id"])
    if g["id"] in state["ignored"]:
        g["state"] = "ignored"
    elif fx and g["last"] <= fx["at"]:
        g["state"] = "fixed"
    elif fx:
        g["state"] = "recurred"
    elif g["why"] == "allowed":
        g["state"] = "fixed"
    else:
        g["state"] = "open"
    if fx:
        g["fix_applied"] = fx
    g["fixable"] = bool(g["fixes"])
    return g


def do_scan(hours, files=None):
    st = selinux_status()
    if hours and hours > 0:
        cutoff = time.time() - hours * 3600
    else:
        cutoff = boot_time()
    records, sources, errors = collect(cutoff, files)
    groups = group_records(records)
    state = load_state()
    deep = st["enabled"] or bool(files)
    for g in groups:
        analyse(g, state, deep=deep)
    return {
        "status": st,
        "cutoff": cutoff,
        "scanned_at": time.time(),
        "sources": sources,
        "errors": errors,
        "issues": groups,
        "history": state["history"][-50:],
    }


def boot_time():
    for line in (read_text("/proc/stat", "") or "").splitlines():
        if line.startswith("btime "):
            return float(line.split()[1])
    return 0.0


# -------------------------------------------------------------------- fixes

def require_root():
    if os.geteuid() != 0:
        raise PermissionError("administrative access (root) is required")


def apply_fix(req):
    """req: {id, summary, fix: {...}, lines: [...]}"""
    require_root()
    fix = req.get("fix") or {}
    kind = fix.get("type")
    iid = str(req.get("id", ""))
    if not re.fullmatch(r"[0-9a-f]{10}", iid):
        raise ValueError("bad issue id")
    log = []
    detail = {}
    reboot = False

    if kind == "restorecon":
        paths = [p["path"] if isinstance(p, dict) else p for p in fix.get("paths", [])]
        if not paths:
            raise ValueError("no paths given")
        for p in paths:
            if not p.startswith("/") or not os.path.lexists(p):
                raise ValueError(f"{p}: no such file")
            argv = ["restorecon", "-F", "-v"] + (["-R"] if os.path.isdir(p) and not os.path.islink(p) else []) + ["--", p]
            r = run(argv, check=True)
            log.append("$ " + " ".join(argv))
            log.append(r.stdout.strip() or "(nothing to relabel)")
        detail = {"paths": paths}

    elif kind == "boolean":
        name, value = fix.get("name"), fix.get("value")
        if not isinstance(name, str) or not re.fullmatch(r"\w+", name):
            raise ValueError("bad boolean name")
        if value not in (0, 1):
            raise ValueError("boolean value must be 0 or 1")
        old = boolean_value(name)
        if old is None:
            raise ValueError(f"boolean {name} does not exist in the loaded policy")
        argv = ["setsebool", "-P", name, str(value)]
        run(argv, check=True)
        log.append("$ " + " ".join(argv))
        log.append(f"{name}: {old} -> {value}")
        detail = {"name": name, "old": old, "new": value}

    elif kind == "port":
        ports = fix.get("ports") or []
        if not ports:
            raise ValueError("no ports given")
        done = []
        for p in ports:
            port, proto, ptype = p.get("port"), p.get("proto"), p.get("type")
            if not (isinstance(port, int) and 0 < port < 65536) or proto not in ("tcp", "udp", "sctp") \
                    or not re.fullmatch(r"\w+_port_t", str(ptype)) or ptype not in port_types():
                raise ValueError(f"bad port request {p!r}")
            argv = ["semanage", "port", "-a", "-t", ptype, "-p", proto, str(port)]
            r = run(argv, check=True)
            log.append("$ " + " ".join(argv))
            if (r.stdout + r.stderr).strip():
                log.append((r.stdout + r.stderr).strip())
            done.append({"port": port, "proto": proto, "type": ptype})
        log.append("Restart the service so it binds the port again.")
        detail = {"ports": done}

    elif kind == "fcontext":
        d, setype = fix.get("dir", ""), fix.get("setype", "")
        d = os.path.normpath(d) if d.startswith("/") else d
        if not d.startswith("/") or "\n" in d or not os.path.isdir(d) or d in PROTECTED_DIRS \
                or (d.startswith(PRIVATE_PREFIXES) and not home_subdir_ok(d)) or read_only(d):
            raise ValueError(f"{d}: not a directory that can be relabeled")
        if not re.fullmatch(r"\w+_t", setype):
            raise ValueError("bad SELinux type")
        spec = re.escape(d) + "(/.*)?"
        argv = ["semanage", "fcontext", "-a", "-t", setype, spec]
        run(argv, check=True)
        log.append(f"$ semanage fcontext -a -t {setype} '{spec}'")
        argv = ["restorecon", "-R", "-v", "--", d]
        r = run(argv, check=True)
        log.append("$ " + " ".join(argv))
        log.append(r.stdout.strip() or "(nothing to relabel)")
        detail = {"dir": d, "spec": spec, "setype": setype}

    elif kind == "relabel":
        flag = autorelabel_flag()
        with open(flag, "w"):
            pass
        log.append(f"$ touch {flag}")
        log.append("The whole filesystem will be relabeled at the next boot. This can take a while.")
        reboot = True

    elif kind == "module":
        name = fix.get("name", "")
        if not re.fullmatch(MODULE_PREFIX + r"[a-z0-9_]{1,60}", name):
            raise ValueError("bad module name")
        lines = [l for l in req.get("lines", []) if isinstance(l, str) and "avc:" in l]
        if not lines:
            raise ValueError("no denial lines given")
        with tempfile.TemporaryDirectory() as tmp:
            src = os.path.join(tmp, "denials.log")
            with open(src, "w") as f:
                f.write("\n".join(lines) + "\n")
            r = run(["audit2allow", "-M", name, "-i", src], cwd=tmp, check=True)
            log.append(f"$ audit2allow -M {name}")
            log.append(r.stdout.strip())
            te_path, pp_path = os.path.join(tmp, name + ".te"), os.path.join(tmp, name + ".pp")
            te = read_text(te_path, "")
            expected = fix.get("te")
            if expected and expected.strip() != te.strip():
                raise RuntimeError("the generated policy differs from the one you reviewed; scan again")
            run(["semodule", "-i", pp_path], check=True)
            log.append(f"$ semodule -i {name}.pp")
            os.makedirs(MODULE_DIR, mode=0o755, exist_ok=True)
            shutil.copy(te_path, MODULE_DIR)
            shutil.copy(pp_path, MODULE_DIR)
            log.append(f"Module source kept in {MODULE_DIR}/{name}.te")
        detail = {"name": name}

    else:
        raise ValueError(f"unknown fix type {kind!r}")

    state = load_state()
    entry = {"id": iid, "type": kind, "at": time.time(), "summary": req.get("summary", ""),
             "detail": detail, "undone": False}
    state["fixed"][iid] = entry
    state["ignored"].pop(iid, None)
    state["history"].append(entry)
    save_state(state)
    return {"ok": True, "log": "\n".join(log), "reboot": reboot, "entry": entry}


def undo_fix(iid):
    require_root()
    state = load_state()
    entry = next((h for h in reversed(state["history"]) if h["id"] == iid and not h.get("undone")), None)
    if not entry:
        raise ValueError("no fix recorded for this issue")
    d = entry.get("detail", {})
    if entry["type"] == "boolean":
        run(["setsebool", "-P", d["name"], str(d["old"])], check=True)
        msg = f"{d['name']} set back to {d['old']}"
    elif entry["type"] == "module":
        run(["semodule", "-r", d["name"]], check=True)
        msg = f"module {d['name']} removed"
    elif entry["type"] == "port":
        for p in d["ports"]:
            run(["semanage", "port", "-d", "-t", p["type"], "-p", p["proto"], str(p["port"])], check=True)
        msg = "port label(s) removed: " + ", ".join(f"{p['port']}/{p['proto']}" for p in d["ports"])
    elif entry["type"] == "fcontext":
        run(["semanage", "fcontext", "-d", d["spec"]], check=True)
        run(["restorecon", "-R", "--", d["dir"]], check=True)
        msg = f"label rule for {d['dir']} removed and default labels restored"
    else:
        raise ValueError(f"a {entry['type']} fix can't be undone automatically")
    entry["undone"] = True
    entry["undone_at"] = time.time()
    state["fixed"].pop(iid, None)
    save_state(state)
    return {"ok": True, "log": msg}


def set_ignored(iid, on, summary=""):
    require_root()
    state = load_state()
    if on:
        state["ignored"][iid] = {"at": time.time(), "summary": summary}
    else:
        state["ignored"].pop(iid, None)
    save_state(state)
    return {"ok": True}


def install_tools():
    require_root()
    pkgs = selinux_status()["missing_packages"]
    if not pkgs:
        return {"ok": True, "log": "All tools are already installed."}
    if is_transactional():
        # installs into a new snapshot; active after the next reboot
        argv = ["transactional-update", "--non-interactive", "pkg", "install", "--no-recommends"] + pkgs
        r = run(argv, timeout=1800)
        if r.returncode != 0:
            raise RuntimeError((r.stderr or r.stdout).strip()[-2000:])
        return {"ok": True, "reboot": True,
                "log": "$ " + " ".join(argv) + "\n" + r.stdout.strip()[-4000:]}
    argv = ["zypper", "--non-interactive", "install", "--no-recommends"] + pkgs
    r = run(argv, timeout=1800)
    if r.returncode not in (0, 100, 101, 102, 103):
        raise RuntimeError((r.stderr or r.stdout).strip()[-2000:])
    return {"ok": True, "log": "$ " + " ".join(argv) + "\n" + r.stdout.strip()[-4000:]}


# ---------------------------------------------------------------------- CLI

def fmt_time(ts):
    return datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M")


def print_issue(g, n=None):
    head = f"[{n}] " if n is not None else ""
    flag = "BLOCKED" if g.get("blocked") else ("logged" if g["kind"] == "avc" else "error")
    print(f"{head}{g['summary']}")
    print(f"     {g['count']}x, last {fmt_time(g['last'])}, {flag}, state: {g['state']}  (id {g['id']})")
    for fx in g["fixes"]:
        print(f"     fix: {fx['title']}")
        for c in fx["commands"]:
            print(f"          # {c}")


def cli_list(args):
    res = do_scan(args.hours, args.file)
    st = res["status"]
    print(f"SELinux: {st['mode']}  policy: {st['policy'] or '-'}  sources: {', '.join(res['sources']) or 'none'}")
    if st["missing_packages"]:
        print("Missing tools: zypper install " + " ".join(st["missing_packages"]))
    issues = [g for g in res["issues"] if args.all or g["state"] in ("open", "recurred")]
    if not issues:
        print("No open SELinux problems found.")
    for i, g in enumerate(issues, 1):
        print()
        print_issue(g, i)


def ask(prompt, choices):
    while True:
        try:
            a = input(prompt).strip().lower()
        except EOFError:
            return "q"
        if a == "":
            a = choices[-1]
        if a in choices:
            return a


def cli_review(args):
    res = do_scan(args.hours, args.file)
    issues = [g for g in res["issues"] if g["state"] in ("open", "recurred")]
    if not issues:
        print("No open SELinux problems found.")
        return
    print(f"Found {len(issues)} SELinux problem(s).")
    if ask("Would you like to review and correct them now? [y/N] ", ["y", "n"]) != "y":
        return
    for i, g in enumerate(issues, 1):
        print()
        print_issue(g, f"{i}/{len(issues)}")
        if not g["fixes"]:
            print("     No automatic fix available.")
            if ask("     Ignore it from now on? [y/N] ", ["y", "n"]) == "y":
                set_ignored(g["id"], True, g["summary"])
            continue
        fx = g["fixes"][0]
        if fx["type"] == "module":
            print("\n" + "\n".join("        " + l for l in fx["te"].splitlines()) + "\n")
        a = ask(f"     Apply \"{fx['title']}\"? [y]es / [i]gnore / [q]uit / [N]o ", ["y", "i", "q", "n"])
        if a == "q":
            break
        if a == "i":
            set_ignored(g["id"], True, g["summary"])
            continue
        if a != "y":
            continue
        f = dict(fx)
        if fx["type"] == "boolean":
            o = fx["options"][0]
            f = {"type": "boolean", "name": o["name"], "value": o["value"]}
        try:
            r = apply_fix({"id": g["id"], "summary": g["summary"], "fix": f, "lines": g["lines"]})
            print("     " + r["log"].replace("\n", "\n     "))
        except Exception as ex:  # noqa: BLE001
            print(f"     FAILED: {ex}")


def main():
    ap = argparse.ArgumentParser(prog="selinux-fixer", description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("status")
    for name in ("scan", "list", "review"):
        p = sub.add_parser(name)
        p.add_argument("--hours", type=float, default=24 * 7, help="look back this many hours (0 = since boot)")
        p.add_argument("--file", action="append", help="read audit lines from FILE instead of the system logs")
        if name == "list":
            p.add_argument("--all", action="store_true", help="also show fixed and ignored problems")
    sub.add_parser("apply")
    for name in ("undo", "ignore", "unignore"):
        sub.add_parser(name).add_argument("id")
    sub.add_parser("install-tools")
    args = ap.parse_args()

    try:
        if args.cmd == "status":
            emit(selinux_status())
        elif args.cmd == "scan":
            emit(do_scan(args.hours, args.file))
        elif args.cmd == "list":
            cli_list(args)
        elif args.cmd == "review":
            cli_review(args)
        elif args.cmd == "apply":
            emit(apply_fix(json.load(sys.stdin)))
        elif args.cmd == "undo":
            emit(undo_fix(args.id))
        elif args.cmd in ("ignore", "unignore"):
            summary = ""
            if not sys.stdin.isatty():
                summary = sys.stdin.read().strip()[:300]
            emit(set_ignored(args.id, args.cmd == "ignore", summary))
        elif args.cmd == "install-tools":
            emit(install_tools())
    except (ValueError, RuntimeError, PermissionError, FileNotFoundError, OSError) as ex:
        print(f"selinux-fixer: {ex}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
