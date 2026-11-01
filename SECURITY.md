# Security policy — FALSICORE 0.2

## Supported line

Version `0.2.x` is **experimental**. No guaranteed response SLA or long-term support has been promised. Releases may contain incomplete telemetry or false positives/negatives. Older internal prototypes are unsupported.

## Reporting

Enable **Private vulnerability reporting** in the GitHub repository settings before the public launch. Submit vulnerabilities through that channel; no owner email address is presumed. If private reporting is unavailable, avoid posting exploit details, complete scan logs, personal machine paths, cookies, identifiers or credentials in public issues.

No response-time or maintenance commitment is created by this package. Coordinated disclosure should avoid releasing exploit steps before a fix can be evaluated.

## Security boundary

The default scan is offline, passive and unprivileged. It can be fooled by an already-compromised OS/kernel. Reports contain local security metadata and must remain private. The bundled SHA-256 manifest checks consistency, **not authenticity**. Prefer a checksum from the trusted GitHub release and separate signed/attested provenance where available.
