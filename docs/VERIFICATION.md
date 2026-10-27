# Release verification contract

The delivered `.pyz`, not merely a development checkout, must pass its member
integrity check, embedded unittest suite and actual user/system smoke tests.
A fresh exported checkout must retain every previous regression-test file.
Two builds from the same snapshot must have identical bytes. Test a corrupted
member and an extra untracked member; both must be refused before scanning.
Test Cyrillic/space-containing launch paths. Preserve reports and source data.

## What was and was not measured

Unit/integration/adversarial fixtures, source-pattern checks, branch-aware code
coverage, report checksum/semantic coherence, default-user scans, repeated
baseline comparison, explicit system/deep scans and root-default rejection
are separately recorded. Expected error tests are not failed release gates.
Host telemetry is never included in published evidence logs.

The execution environment is Debian 13 with Python 3.13.5, not the user's
Ubuntu laptop. Ubuntu 24.04 and Python 3.10/3.12/3.14 jobs are configured for
hosted CI but are NOT claimed to have run. Bandit installation was attempted
and blocked by unavailable DNS in the build environment; no Bandit/CodeQL
pass claim is made. The internal AST checker has nine bounded pattern rules,
not general vulnerability-detection completeness.

## Reference boundaries

Python's official zipapp documentation supports direct execution of a Python
archive; it does not certify this application:
https://docs.python.org/3/library/zipapp.html

Python's official shlex documentation describes shell-like lexical analysis,
not complete Bash semantics. The detector exposes that limitation:
https://docs.python.org/3/library/shlex.html

The existing NIST/MITRE mappings in the assurance documents are methodological
references, not certification or measurements of malware-detection efficacy.
A checksum is not a digital signature. An attacker controlling the kernel or
the tool and its manifests can forge internally consistent observations.
