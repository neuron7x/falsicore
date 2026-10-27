# falsicore

**Offline, read-only compromise triage for a single Linux workstation.**

falsicore inspects the machine it runs on and records what it saw. It also
records what it could not see, and why. The result is a private report that
verifies itself. It does not fix anything, send anything, or tell you the
machine is clean.

The name comes from *falsification*. Absence proves nothing: zero findings
mean zero findings *within the inspected scope*, never "no compromise". Each
check says one of three things about itself:

- it fully inspected its defined target;
- it fell short, with a coded reason;
- its view was limited by the chosen scope.

---

## Who it is for

- You suspect a Linux laptop was touched (a phishing link, an unfamiliar
  browser extension, a session you did not open). You want a first, careful
  look before deciding whether to escalate.
- You want that look to be **auditable**: standard library only, no network,
  and a source tree you can read in an afternoon.
- You respond to incidents and need a bounded triage snapshot that keeps
  observations, exposures and visibility gaps apart.

It is **not** an antivirus, an EDR agent, a rootkit detector, or a forensic
imaging tool.

## What makes it different

- **Coverage is a measurement, not a colour.** `PARTIAL` requires a reason code
  from a closed vocabulary, such as `TIMEOUT`, `INPUT_TRUNCATED` or
  `PARSE_UNSUPPORTED`. Scope limits are reported separately and never hidden;
  examples are other accounts' processes in user scope and root-only files.
  `COMPLETED` cannot carry an incompleteness reason. The code enforces both rules.
- **Findings explain themselves.** Each finding has:
  - an observation;
  - the concrete thing it is about: extension name, ID, version, enabled state
    and granted permissions; parent process; executable hash;
  - benign alternatives;
  - the uncertainty;
  - a non-destructive next step.

  No follow-up scripting is needed.
- **Evidence survives the process.** Process findings capture PID, PPID, UID,
  kernel start time, boot ID and executable identity through a pinned `/proc`
  directory descriptor. A process that exits, or a PID that is reused, cannot
  silently change what was recorded.
- **Shell analysis that knows its limits.** A quote-aware lexer finds:
  - literal execution from temporary paths;
  - downloads piped into interpreters;
  - process substitution;
  - command-valued settings such as `PROMPT_COMMAND`, `alias` and `trap`.

  When the program that would run cannot be resolved statically, it says so.
  It never guesses.
- **Package attestation instead of blind trust.** A root-owned file whose
  content matches its dpkg record is labelled as such. Unparsed syntax in it is
  then a stated trust assumption, not a hidden gap.

## What it reads

All collection is passive. Files are read through no-follow directory
descriptors, with size and count limits. Commands come from a fixed allowlist
in `/usr/bin`, `/usr/sbin`, `/bin`, `/sbin`. They run without a shell, under a
minimal environment, with per-command deadlines clamped to the whole-scan
budget, and in their own process group, which is killed afterwards.

| Area | Sources |
|---|---|
| Processes | `/proc/<pid>/{stat,status,exe,cmdline}`: volatile or deleted executables, root running user paths, browser launch flags (sandbox and trust relaxation, DevTools pipe vs port) |
| Network | `ss` snapshot: listeners and non-loopback binds, debug-port listener correlation, process attribution where visible |
| Persistence | systemd units (system, user, vendor), cron (`/etc/cron*`, user crontab), XDG autostart, shell start-up files and the files they source, `~/.ssh/authorized_keys`, `/etc/sudoers.d` (system scope), `/etc/ld.so.preload` |
| Browsers | Chrome, Chromium, Brave, Edge, Firefox (also Snap and Flatpak paths): extension manifests, preference state (enabled and granted permissions), Firefox add-on metadata and signatures, native-messaging hosts, managed policies |
| Authentication | `journalctl` auth/authpriv facility, 30 days, no raw messages kept |
| Packages | APT sources (trust overrides), dpkg metadata, `dpkg --verify` (deep profile) |
| Kernel | taint, modules, LSMs, `aa-status`, Secure Boot (system scope), recent kernel-log sample |

It does not read cookies, passwords, history, private keys or full process
arguments.

## Run

From a checkout:

```bash
./run.sh                       # standard profile, current user, compares with your last compatible run
./run.sh --profile quick       # faster, omits auth/packages/kernel
./run.sh --profile deep        # adds dpkg --verify
```

Or as a single file, built deterministically from this tree:

```bash
python3 tools/build_app.py ~/falsicore.pyz
python3 -I ~/falsicore.pyz verify-app && python3 -I ~/falsicore.pyz self-test
python3 -I ~/falsicore.pyz
```

Progress goes to stderr: a phase line per collector and a heartbeat every
10 s. The interpreted result goes to stdout. The report lands in
`~/falsicore-runs/run-*`: mode `0700`, with `dashboard.html` (offline, no
JavaScript, strict CSP), Markdown and JSON. Ctrl-C stops the scan, kills the
probes it started, and names the incomplete run folder.

```bash
python3 -I falsicore.py verify  ~/falsicore-runs/run-XXXX                 # hash manifest + semantic recomputation
python3 -I falsicore.py explain ~/falsicore-runs/run-XXXX                 # full Ukrainian interpretation
python3 -I falsicore.py explain --share-safe ~/falsicore-runs/run-XXXX    # without paths, IDs, PIDs
```

A system-wide pass is opt-in and explicit:

```bash
sudo /usr/bin/python3 -I "$PWD/falsicore.py" scan --scope system --target-user "$USER" --profile deep
```

## Reading the result

| Class | Meaning |
|---|---|
| `INDICATOR` | An observation that warrants corroboration. Not a confirmed breach. |
| `EXPOSURE` | An accessible surface or capability. Not intent. |
| `HARDENING` | A configuration that weakens defence. |
| `CONTEXT` | A fact that is usually benign. |

| Check state | Meaning |
|---|---|
| `COMPLETED` | The defined target was fully inspected. Scope limits may still be listed. |
| `PARTIAL` | The target was not fully inspected; `reason_codes` say why. |
| `FAILED` | The collector failed; its uncommitted observations were rolled back. |
| `SKIPPED` | Excluded by the profile, or the budget was exhausted. |

Exit `0` means the workflow completed. It does **not** mean the machine is
clean. With `--strict-exit`, `10` means suspicious and `11` inconclusive.

## Trust model, briefly

- **Inside scope:** user-space persistence, over-privileged browser extensions
  and native hosts, unexpected listeners, risky scheduler and start-up entries,
  loader preload, insecure package sources.
- **Outside scope:** a kernel- or firmware-level adversary that controls what
  the running OS reports; deleted history; account sessions on remote
  services; encrypted traffic contents.
- **Report integrity** is a local hash manifest plus semantic recomputation of
  the verdict, the counts and the baseline. It catches accidental or naive
  tampering. It is not a signature and cannot authenticate a host that is
  already compromised.

Details: [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md),
[`docs/DETECTORS.md`](docs/DETECTORS.md), [`docs/AUDIT.md`](docs/AUDIT.md).

## Verify the code yourself

```bash
sha256sum -c SOURCE_MANIFEST.sha256 && python3 tools/build_release.py --check-manifest
python3 -m unittest discover -s tests -q
python3 tools/code_audit.py . --fail-on high
python3 tools/build_full.py /tmp/a && python3 tools/build_full.py /tmp/b && cmp /tmp/a/*.zip /tmp/b/*.zip
```

CI ([`verify.yml`](.github/workflows/verify.yml)) runs these on Python
3.10–3.14 with read-only permissions and commit-pinned actions. It also runs
ruff (correctness subset), bandit, and a branch-coverage gate.

## Limits worth stating twice

- Coverage percentages measure exercised code, not detection sensitivity. No
  validation against a real malware corpus has been performed.
- A live scan of a compromised system is evidence collected by that system.
- An extension with broad permissions has a capability. Local metadata cannot
  show whether it used that capability.
- The whole-scan deadline is cooperative: probes are hard-bounded, but a
  blocking read inside a collector is not interrupted.

## Status

`0.1.3`, alpha. Report schema `falsicore.summary.v4`. Reports from 0.1.2 are
read as `LEGACY` and are never compared with new ones.

## License

[Apache-2.0](LICENSE).
