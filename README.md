# SELinux Fixer for Cockpit

A [Cockpit](https://cockpit-project.org) page for **openSUSE Tumbleweed**,
**Leap 16.1** and **Kalpa** that finds SELinux denials in the system logs, explains them, and asks whether you
want to fix them.

When you open **Tools → SELinux Fixer**, the page scans the logs. If it finds
problems it asks:

> **3 SELinux problems found.** Would you like to review them and correct the
> issues now? Nothing is changed until you approve each fix.

**Review and fix** walks through the problems one at a time. For each one it shows
what was denied, the fix it recommends, any alternatives, and the exact
commands it will run. Choose **Apply fix**, **Skip**, or **Ignore this
problem**. The question is asked once per browser session. After that, use
**Review & fix** in the toolbar.

## Where denials come from

| Source | Used when |
|---|---|
| `/var/log/audit/audit.log` (via `ausearch`) | `auditd` is installed and running |
| systemd journal, audit messages | always, so it works without `auditd` too |
| systemd journal, kernel messages | catches `avc:` lines the kernel logs when no audit daemon listens |

The same event found in more than one source is counted once. Denials with the
same program, source type, target type and object class are grouped into one
problem, so 500 identical log lines show up as one problem seen 500 times.

## Fixes, safest first

| Fix | When it is offered | Undo |
|---|---|---|
| **Restore default label** (`restorecon -F`) | The file or directory exists and its label *type* differs from the policy default, usually because it was moved with `mv` | – (it puts back the default label) |
| **Label a custom location** (`semanage fcontext -a` + `restorecon -R`) | A known service (Apache, Samba, FTP, NFS, rsync, BIND, MariaDB, PostgreSQL, containers) uses data in a non-standard directory such as `/data/www`, whose default label doesn't fit | Yes |
| **Label a port** (`semanage port -a`) | A service binds a port that SELinux associates with something else or nothing, for example Apache on 8765 | Yes |
| **Turn on a boolean** (`setsebool -P`) | `audit2why` says a policy boolean controls this access. The boolean's description from `semanage boolean -l` is shown. | Yes |
| **Relabel at next boot** (`touch /.autorelabel`) | The target is `unlabeled_t` / `file_t` | – |
| **Local policy module** (`audit2allow -M`, `semodule -i`) | Nothing else applies (missing allow rule) | Yes (`semodule -r`) |

Most AVC records only contain the file's base name plus device and inode
(full paths need audit syscall rules). SELinux Fixer looks up the full path from
the inode with `btrfs inspect-internal inode-resolve`, `debugfs` (ext4) or
`find -inum`, and checks each match against the name. That lets it
recommend `restorecon` for a file that was moved into place, where
setroubleshoot suggests turning on a broad boolean such as
`httpd_read_user_content`.

Denials of targets that were `unlabeled_t` when logged but are labeled now
(common very early at boot) are shown as *nothing to fix* rather than
triggering a full relabel.

The policy module is the last resort. The page shows the generated `.te` rule,
and you must tick *"I've read this rule…"* before you can apply it. It is
labelled *Changes policy*. When the module is installed, the helper rebuilds it
and refuses to install it if it differs from what you reviewed. Modules are named
`sefix_<domain>_<id>`, and their sources are kept in
`/var/lib/cockpit-selinux-fixer/modules/`.

Problems that cannot be fixed automatically (constraint violations, role
problems, `SELINUX_ERR` messages) are listed with an explanation.

### State

`/var/lib/cockpit-selinux-fixer/state.json` holds:

- **fixed** — issue ID and fix time. A problem counts as fixed while no new
  denial for it appears. If it comes back, it is shown again as *Came back
  after fix*.
- **ignored** — problems you chose to ignore (see the *Ignored* tab).
- **history** — every fix applied, with Undo for booleans, modules, port labels and location labels.

## Requirements

- openSUSE Tumbleweed or Leap 16.x with SELinux enabled (the default for new
  Tumbleweed installs since 2025, and for Leap 16), or Kalpa/Aeon/MicroOS (see
  below). On an AppArmor system the page says that SELinux isn't active.
- Cockpit ≥ 300
- `policycoreutils`, `policycoreutils-python-utils`, `checkpolicy`, and
  optionally `audit`. If any are missing, the page offers to install them.
- Administrative access in Cockpit to read the audit log and apply fixes.

## Leap 16.1

Tested on Leap 16.1 (SELinux enforcing out of the box, all tools installed).
It behaves like Tumbleweed: the scenarios below gave the same fixes and
results, the fixes survived a reboot, and Undo works. Install with `make
install` or the RPM, as on Tumbleweed (Leap has no `make` by default:
`sudo zypper in make`).

## Bug report links

When a denial has no fix and looks like a policy bug, the page links to
openSUSE Bugzilla with the product, version and *SELinux* component already
filled in for the running system: *openSUSE Distribution / Leap 16.1* on Leap,
*openSUSE Kalpa* on Kalpa, and *openSUSE Tumbleweed* on Tumbleweed, Slowroll,
Aeon and MicroOS.

## Kalpa, Aeon and MicroOS

Tested on Kalpa (SELinux enforcing). On these systems `/` is read-only and
software is installed with `transactional-update`. SELinux Fixer detects this
and handles it:

- **Install tools** runs `transactional-update pkg install` and tells you to reboot.
- **Relabel** uses `/etc/selinux/.autorelabel` (the root filesystem is read-only).
- **restorecon** is never offered for files on the read-only system snapshot.
- **Fixes survive updates.** Booleans, port labels and location labels live in
  `/etc/selinux`, which `transactional-update` copies into the new snapshot.
  Fixes made after an update snapshot was created but before the reboot are
  carried over too (tested).
- **Containers:** a Podman or Distrobox container that can't read a folder
  shared from your home directory gets a **Label the folder as
  `container_file_t`** fix, never a policy module that would let every
  container read your home directory. The home directory itself and hidden
  folders such as `~/.ssh` are never relabeled.
- If `/etc/selinux/config` says enforcing but the kernel was started with
  `security=` set to something else, the page explains how to turn SELinux on.

Installing on Kalpa: `make` isn't available, so link the checkout by hand, or
install the RPM in a transaction:

```sh
mkdir -p ~/.local/share/cockpit
ln -sfn "$PWD/src" ~/.local/share/cockpit/selinux-fixer     # just for your user
sudo transactional-update pkg install ./cockpit-selinux-fixer-*.noarch.rpm   # system-wide, then reboot
```

## Install

```sh
# development: Cockpit loads the page straight from this checkout
make devel-install        # links ~/.local/share/cockpit/selinux-fixer -> src/
# then reload Cockpit and open Tools → SELinux Fixer

# system-wide
sudo make install

# RPM
make rpm                  # dist/noarch/cockpit-selinux-fixer-*.rpm and a source RPM
```

### Open Build Service

`make obs` puts the three files an OBS package needs in `dist/obs/`:
the source tarball, `cockpit-selinux-fixer.spec` and
`cockpit-selinux-fixer.changes`. Upload them to your OBS package, or with `osc`:

```sh
osc checkout home:<user> && cd home:<user>
osc mkpac cockpit-selinux-fixer && cd cockpit-selinux-fixer
cp /path/to/dist/obs/* . && osc add * && osc commit -m "Initial package"
```

To release a new version, change `Version:` in the spec and `VERSION` in the
Makefile, add an entry with `osc vc`, and run `make obs` again.

## Tested scenarios

Tested on Tumbleweed and on Leap 16.1 (SELinux enforcing, targeted policy) with Apache:

| Broken setup | Suggested fix | Result |
|---|---|---|
| `index.html` created in `~` and moved to `/srv/www/htdocs` | `restorecon` (path found from inode) | 403 → 200 |
| `Alias /datatest /data/www` | `semanage fcontext … '/data/www(/.*)?'` | 403 → 200 |
| `Listen 8765` (port owned by `lirc_port_t`) | `semanage port -a -t http_port_t -p tcp 8765` | Apache fails to start → starts |
| `ProxyPass` to another web server | `setsebool -P httpd_can_network_connect 1` | 503 → proxied |

Undoing each fix brought the denial back.

On Kalpa and Leap 16.1: `podman run -v ~/sharetest:/x alpine cat /x/file.txt` → *Permission
denied*. Suggested fix: `semanage fcontext -a -t container_file_t
'/home/nhaas/sharetest(/.*)?'` → the container reads the file, and the fix is
still in place after a `transactional-update` and reboot.

## Command line

`sefix.py` is the backend. It is also installed as `selinux-fixer`:

```sh
sudo selinux-fixer review              # asks before each fix, like the page
sudo selinux-fixer list --hours 24     # readable summary
sudo selinux-fixer list --all          # include fixed and ignored problems
sudo selinux-fixer scan                # JSON, what the page reads
sudo selinux-fixer undo <id>
selinux-fixer list --file tests/sample-audit.log   # try it on saved audit lines
```

## Layout

```
src/manifest.json   Cockpit menu entry (Tools → SELinux Fixer)
src/index.html      page
src/app.js          UI: scan, list, first-visit prompt, review wizard, history
src/app.css         styles (follows Cockpit's light/dark setting)
src/sefix.py        backend + CLI: log reading, grouping, audit2why, fixes, state
cockpit-selinux-fixer.spec, .changes   RPM / OBS packaging
tests/              sample audit log used by `make check`
```
