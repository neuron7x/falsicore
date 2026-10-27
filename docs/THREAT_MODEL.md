# Threat model

## Assets

Local browser identities, credentials, Linux user files, privileged system state, service/persistence configuration, security logs, and the private scan report. The software primarily reads metadata instead of extracting credentials.

## Adversaries and events

- Social engineering, malicious extension, browser session theft and browser code execution (not inferred merely from Instagram communication).
- User-space malware with persistence through services, shell startup, cron, XDG, SSH or remote access software.
- Privileged compromise capable of altering logs/process tables/files; **beyond live-scan trust**.
- Malicious or accidentally compromised project ZIP, GitHub workflow or dependency.
- Adversarial content in local files/logs attempting to instruct an AI assistant; treated as data, never evaluated.

## Trust boundaries

1. **Source distribution:** the source manifest is not cryptographic publisher authentication. An independently trusted release hash/signature is required for provenance.
2. **Collection:** executable names and the collector's read-only argument shapes are allowlisted; no shell. Direct-child exit and stdout EOF are both required. Timeouts, capped output and file-access failures are reported.
3. **Analysis:** fixed pure rules, no cloud model, no dynamic code evaluation. Findings never establish confirmed intrusion.
4. **Output:** private file system, no remote uploads, escaped offline HTML. Manifest hashes plus semantic cross-checks enforce local coherence, **not** independent attestation.
5. **Privilege:** system scan explicitly opt-in; kernel/firmware and previously deleted evidence cannot be ruled out.

## Known residual risks

Live filesystem access can race with hostile changes; some kernel pseudo-files and symlinked distro paths require special handling. Commands may observe truncated or permission-limited telemetry. Browser profile discovery does not prove that all browser instances or linked accounts were assessed. Scheduled checks accumulate sensitive reports. Disconnected hosts cannot validate account-side sessions in Meta/Instagram or third-party providers.
