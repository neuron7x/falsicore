# falsicore

**Offline, read-only compromise triage for a single Linux workstation.**

falsicore inspects the machine it runs on, records what it could and could not
see, and writes a private, self-verifying report. It does not fix anything,
send anything, or tell you the machine is clean.

The name comes from *falsification*. A scan can rule nothing in by absence:
zero findings mean zero findings *within the inspected scope*, never "no
compromise". Every check states what it covered, what limited it, and why.

---

## Who it is for

- You suspect a Linux laptop was touched (a phishing link, an unfamiliar
  browser extension, a session you did not open) and want a first, careful
  look before deciding whether to escalate.
- You want that look to be **auditable**: one Python file, no dependencies,
  no network, and source you can read in an afternoon.
- You respond to incidents and need a bounded triage snapshot that keeps
  observations, exposures and visibility gaps apart.

It is **not** an antivirus, an EDR agent, a rootkit detector, or a forensic
imaging tool.

## What it reads

All collection is passive. Files are read with size and count limits.
Commands run without a shell, from a fixed allowlist resolved only in
`/usr/bin`, `/usr/sbin`, `/bin`, `/sbin`, under a minimal environment and a
per-command deadline.

| Area | Sources |
|---|---|
| Processes | `/proc/<pid>/` — executable path, deleted-binary flag, volatile locations, selected browser launch flags |
| Network | `ss` snapshot — listeners, non-loopback binds, process attribution where visible |
| Persistence | systemd units (system and user), cron (`/etc/cron*`, user crontab), XDG autostart `.desktop`, shell startup files (`.bashrc`, `.profile`, `.zshrc`, fish), `~/.ssh/authorized_keys`, `/etc/sudoers.d` |
| Browsers | Chrome, Chromium, Brave, Edge, Firefox (including Snap and Flatpak profile paths): extension manifests, host permissions, content-script matches, native-messaging hosts, managed policies |
| Authentication | `journalctl` (bounded line count, JSON output) |
| Packages | `/etc/apt/sources.list*`, `/var/lib/dpkg/info`, `dpkg --verify` |
| Kernel | `/proc/modules`, taint state, `kptr_restrict`, `dmesg_restrict`, `ptrace_scope`, unprivileged BPF, active LSMs, `aa-status`, `/etc/ld.so.preload`, Secure Boot via `mokutil --sb-state` |

Shell and scheduler content is analysed **statically**. It is never sourced,
expanded or executed. The lexer is deliberately incomplete. Constructs it
cannot resolve, such as complex expansions and heredocs, are reported as
analysis limits rather than as clean.

The tool targets Debian and Ubuntu desktops. On other distributions, missing
tools show up as `UNAVAILABLE`, not as passed checks.

## What it will not do

- connect to any network endpoint;
- invoke `sudo`, or run as root unless explicitly launched that way;
- install, modify, disable or delete anything on the host;
- execute files it inspects;
- copy cookies, passwords, history or full process arguments into reports;
- attribute activity to an actor or declare the system safe.

## Run

Requirements: Linux and Python 3.10 or newer, from the standard library only.

```bash
python3 tools/build_app.py ~/falsicore.pyz     # deterministic single-file build
python3 -I ~/falsicore.pyz verify-app          # check embedded file set
python3 -I ~/falsicore.pyz scan --profile standard --auto-compare
```

The scan prints the location of a private report directory under
`~/falsicore-runs/run-*` (mode `0700`) containing `dashboard.html`
(offline, no JavaScript, strict CSP), Markdown, and JSON.

```bash
python3 -I ~/falsicore.pyz verify  ~/falsicore-runs/run-XXXX   # manifest + semantic checks
python3 -I ~/falsicore.pyz explain ~/falsicore-runs/run-XXXX   # readable conclusion (Ukrainian)
```

| Profile | Collectors | Budget |
|---|---|---|
| `quick` | environment, processes, network, persistence, browsers | 35 s |
| `standard` | adds auth, packages, kernel | 120 s |
| `deep` | same, larger limits | 240 s |

A system-wide pass is opt-in and explicit:

```bash
sudo /usr/bin/python3 -I ~/falsicore.pyz scan --scope system --target-user "$USER" --profile deep
```

## Reading the result

| Class | Meaning |
|---|---|
| `INDICATOR` | An observation that warrants corroboration. Not a confirmed breach. |
| `EXPOSURE` | An accessible surface or capability, such as a broad extension permission or an exposed listener. Not intent. |
| `HARDENING` | A configuration choice that weakens defence. |
| `CONTEXT` | A fact that is usually benign, such as a login or file drift. |

| Check state | Meaning |
|---|---|
| `COMPLETED` | Ran within its bounds. |
| `PARTIAL` | Ran, but visibility was limited by permissions, missing history, truncation or unsupported syntax. |
| `FAILED` | The collector failed. Its uncommitted observations were rolled back. |

Exit `0` means the workflow completed. It does **not** mean the machine is
clean. With `--strict-exit`, `10` means suspicious and `11` means inconclusive.

## Trust model, briefly

- **Inside scope:** user-space persistence, malicious or over-privileged
  browser extensions, unexpected listeners, risky scheduler and startup
  entries, loader preload, insecure package sources.
- **Outside scope:** a kernel- or firmware-level adversary that controls what
  the running OS reports; deleted history; account-side sessions on remote
  services; encrypted traffic contents.
- **Report integrity** is a local hash manifest plus semantic cross-checks.
  It detects accidental or naive tampering. It is not a signature, and it
  cannot authenticate a host that is already compromised.

Full model: [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md). Detector catalogue:
[`docs/DETECTORS.md`](docs/DETECTORS.md).

## Verify the code yourself

```bash
sha256sum -c SOURCE_MANIFEST.sha256
python3 -m unittest discover -s tests -q
python3 tools/code_audit.py . --fail-on high     # bundled AST pattern audit
python3 tools/build_app.py /tmp/a.pyz && python3 tools/build_app.py /tmp/b.pyz && cmp /tmp/a.pyz /tmp/b.pyz
```

CI ([`verify.yml`](.github/workflows/verify.yml)) runs the same steps on
Python 3.10–3.14 with read-only permissions and SHA-pinned actions.

**Known issue.** Four subprocess-lifecycle tests launch the test interpreter
with `LC_ALL=C` and without `-I`. On hosts whose user `site-packages` contain
`.pth` files with non-ASCII paths, the child interpreter fails before it
starts, and those tests report a false failure. The scanner's own probes are
not Python and are unaffected.

## Limits worth stating twice

- Coverage percentages measure exercised code, not detection sensitivity.
  No validation against a real malware corpus has been performed.
- A live scan of a compromised system is evidence collected by that system.
- An extension with broad permissions is a capability. Whether it abused
  that capability cannot be established from local metadata.

## Status

`0.1.2`, alpha. The interfaces and the report schema may change.

## License

[Apache-2.0](LICENSE).
