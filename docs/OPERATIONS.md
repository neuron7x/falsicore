# Operating FALSICORE

## Before execution

1. Verify the release ZIP SHA-256 against the checksum from the trusted publishing account. A checksum stored *inside* the same ZIP does not authenticate the publisher.
2. Inspect source when possible, then run only as the normal user. Do not run an untrusted ZIP as root.
3. Allocate at least 32 MiB free space. Reports are created under `~/falsicore-runs` with `0700` directory and `0600` file permissions.
4. If an active compromise is suspected, do not erase data or run remediation before considering preservation of volatile evidence.

## Commands

| Operation | Command |
|---|---|
| Default triage | `./run.sh` |
| Fast check | `./run.sh --profile quick` |
| Wider metadata | `./run.sh --profile deep` |
| Incident time | `./run.sh --incident-at '2026-10-27T12:00:00+02:00'` |
| Review scheduler safely | `python3 -I falsicore.py monitor plan` |
| Enable scheduler explicitly | `python3 -I falsicore.py monitor enable` |
| Disable scheduler explicitly | `python3 -I falsicore.py monitor disable` |
| Root metadata scan (opt-in) | `sudo /usr/bin/python3 -I "$PWD/falsicore.py" scan --scope system --profile deep --target-user "$USER"` |
| Verify run | `python3 -I falsicore.py verify /path/to/exact/run` |
| Explain run | `python3 -I falsicore.py explain /path/to/exact/run` |

## Report interpretation

`SUSPICIOUS_ACTIVITY_REQUIRES_INVESTIGATION` means a heuristic indicator warrants review; it is not a confirmed intrusion. `INCONCLUSIVE_DUE_TO_VISIBILITY_LIMITATIONS` means material telemetry or permissions were insufficient. `NO_COMPROMISE_INDICATORS_OBSERVED` means no configured indicator was seen in completed essential checks; it is not an all-clear for the system.

`summary.json` records the rule/version, covered and missing checks, digest, and baseline identity. `private_index.json` contains raw local path/endpoint mappings; *never upload it*. An offline HTML report is constructed with escaped data and a restrictive content security policy, without JavaScript or remote assets.

## Failure and maintenance

- If a module fails, its partial observations are discarded; the coverage matrix records `FAILED`.
- Commands use fixed executable allowlists, no shells, bounded output/timeouts and best-effort child-process-group cleanup.
- Scheduling is opt-in, local, and creates no remote notifications; manually inspect disk usage and report retention.
- Hash manifests show whether bytes match the locally recorded versions, not whether they came from a trusted origin.
- A first-run baseline can already contain malware; comparing against it does not prove benign activity.
- Kernel/root compromise and offline account access require independent investigation from trusted media/provider records.
