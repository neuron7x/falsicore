# Threat model

## Assets

Local browser identities, credentials, Linux user files, privileged system state, service/persistence configuration, security logs, and the private scan report. The software primarily reads metadata instead of extracting credentials.

## Adversaries and events

- Social engineering, malicious extension, browser session theft and browser code execution (never inferred from the content of any communication).
- User-space malware with persistence through services, shell startup, cron, XDG, SSH or remote access software.
- User-space or kernel rootkits that hide processes, modules or sockets from one kernel interface; detected only while the second interface still disagrees (`crossview`), never when both are hooked.
- Privileged compromise capable of altering logs/process tables/files; **beyond live-scan trust** — the offline image mode (`--root`) is the complementary method and names what it cannot see.
- Tampering with a package database together with the files it describes (dpkg, rpm, pacman, apk records are consistency checks, not attestation).
- Malicious or accidentally compromised project ZIP, GitHub workflow or dependency.
- Adversarial content in local files/logs attempting to instruct an AI assistant; treated as data, never evaluated.

## Trust boundaries

1. **Source distribution:** the source manifest is not cryptographic publisher authentication. An independently trusted release hash/signature is required for provenance.
2. **Collection:** executable names and the collector's read-only argument shapes are allowlisted; no shell. Direct-child exit and stdout EOF are both required. Timeouts, capped output and file-access failures are reported.
3. **Analysis:** fixed pure rules, no cloud model, no dynamic code evaluation. Findings never establish confirmed intrusion.
4. **Output:** private file system, no remote uploads, escaped offline HTML. Manifest hashes plus semantic cross-checks enforce local coherence, **not** independent attestation.
5. **Privilege:** system scan explicitly opt-in; kernel/firmware and previously deleted evidence cannot be ruled out.
6. **Offline image:** nothing live is consulted about the image; live-only checks are declared `SKIPPED/LIVE_ONLY_NOT_IN_OFFLINE_IMAGE` and leave the essential set. The image's own `/etc/passwd`, crontab spool, journal directory and package records are the sources; the operator's mount options (read-only, `nosuid`, `nodev`) are the operator's responsibility.
7. **Measurement:** the validity table measures recall on planted artifact shapes and silence on their benign twins; the mutation table measures the test suite. Neither is a statement about malware in the field (`docs/ASSURANCE.md`, measurement contract).

## Known residual risks

Live filesystem access can race with hostile changes; a candidate hidden process is confirmed by a second listing and probe, and listener differences by two `/proc/net` snapshots, but a process or socket that lives shorter than the confirming pass is not reported. Some kernel pseudo-files and symlinked distro paths require special handling (`/proc/self`, `/proc/net`, `/etc/os-release`, `/lib`). Commands may observe truncated or permission-limited telemetry. Browser profile discovery does not prove that all browser instances or linked accounts were assessed. Scheduled checks accumulate sensitive reports. A disconnected host cannot validate account-side sessions at any online service. The PID sweep takes a few seconds on hosts with `kernel.pid_max` at its maximum and is budget-bounded.
