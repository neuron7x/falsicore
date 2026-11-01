# Mutation testing

Coverage says a line ran; it does not say a test would notice if the line
were wrong (Inozemtseva & Holmes, ICSE 2014). Mutation testing asks that
second question directly (DeMillo, Lipton & Sayward, 1978; Jia & Harman,
2011): insert one plausible fault, run the tests, see whether anything fails.

## Tool

`tools/mutate.py` is standard-library only. Operators: comparison relaxation
(`<`↔`<=`, `>`↔`>=`, `==`↔`!=`, `in`↔`not in`, `is`↔`is not`), boolean swap
(`and`↔`or`), `not` removal, `if` negation, integer shift (`n+1`, `0`),
boolean flip, `return` → `return None`, `continue`↔`break`, augmented
assignment swap, deletion of a call statement. String literals are **not**
mutated: messages are not behaviour, and the 0.1.3 baseline below shows they
dominate the noise.

Each mutant is written into its own copy of the tree, the source manifest is
regenerated there (the manifest gate must not kill mutants by accident), and
the tests that executed the mutated line run with fail-fast. Test selection
comes from coverage.py dynamic contexts (`tools/mutate.py --coverage`, one
suite run); without them the whole suite runs per mutant. A mutant on a line
that no test executes is `NO_TESTS`, the strongest signal of all.

```bash
python3 tools/mutate.py --coverage               # record per-test contexts (once per change)
python3 tools/mutate.py --diff origin/main        # the pull-request gate: mutants on changed lines only
python3 tools/mutate.py --module detectors        # one module
python3 tools/mutate.py --all --workers 4         # the weekly whole-package run
python3 tools/mutate.py --retry run.json          # only the open items of an earlier --json result (killer-writing cycle)
```

Exit status 1 when a mutant `SURVIVED`, has `NO_TESTS`, timed out or errored.
A line may carry `# no mutate: <reason>` when a mutation there is provably
equivalent or is not behaviour (a log string, a documented tunable); the
reason is mandatory and the tool reports the line as `ANNOTATED`. Survivors
are candidates, never verdicts: equivalence is shown, not assumed.

## Policy

- **Pull requests:** `mutate --diff` on the changed runtime lines must leave
  no survivor (CI job `mutation-diff`). New code arrives with the tests that
  pin it.
- **Weekly:** `mutate --all` on `main` (workflow `mutation.yml`) uploads the
  full table as an artifact; the open-item count must not grow between runs.
  The table is a work list, ranked by module.

## Baseline (external measurement, 0.1.3, commit 81b5345)

Measured before this tool existed, by an independent run of mutmut 3.3.1's
libcst operators plus return→None, test negation and call deletion, one full
suite per mutant, 12 workers, 70 min: **14 675 mutants, 8 236 killed (56 %),
6 390 survived, 48 timeouts, 1 suspicious.** Of the survivors 3 348 were
string mutations and 1 527 default-argument removals; the behavioural
remainder was concentrated in `collectors.py` (1 449), `shell_syntax.py`
(369) and `report.py` (328). Representative survivors that were real test
gaps, now closed by `tests/test_mutation_killers.py`: the severity of
`EXECUTABLE_IN_VOLATILE_PATH` for root versus user, the `and` in
`ROOT_RUNNING_USER_PATH`, the exact size bound of `safe_json_parse`, the
`debug_port` range, every return value of `endpoint_class`, and
`interpret_verdict` for low-severity indicators.

## First in-repo run (0.2.0, `detectors.py`)

`tools/mutate.py --module detectors`: 307 mutants, 303 killed, 4 open before
review → two annotated as equivalent (`split(..., 1)[0]` and
`rsplit(..., 1)[-1]` do not change for a larger maxsplit) and one dead
parameter removed (`redact_untrusted_text(limit)` was never read) → **0 open**.
The run also refuted the tool itself twice before it was trusted: worker
threads shared tree copies by index and could run one mutant's tests against
another's source (now a queue hands each running mutant its own tree), and
coverage contexts attribute a `def` line to import time, so default-argument
mutants were `NO_TESTS` until selection fell back to the enclosing function.

## In-repo baseline per module (0.2.0, before the killer tests of PR #13)

| Module | Mutants | Killed | Survived | Hung | Open items |
|---|---:|---:|---:|---:|---:|
| `detectors.py` | 307 | 303 → 305 | 4 → 0 | 0 | 0 (2 annotated, 1 dead parameter removed) |
| `shell_syntax.py` | 811 | 645 | 139 | 27 | 139 |
| `report.py` | 285 | 197 | 85 | 3 | 85 |
| `safety.py` | 287 | 194 | 90 | 3 | 90 |

A hung mutant (`TIMEOUT`) is noticed by the run and is not an open item. The
survivors of `shell_syntax` clustered in the quote-aware scanners inside
`$(…)`, here-document line accounting, process substitution and the
stdin-code paths; those of `report` in manifest-line validation, the
semantic consistency branches and baseline selection; those of `safety` in
the executor's bounds, exit-code and environment handling and the private
run directory. `tests/test_{shell,report,safety}_mutation_killers.py` target
them; the re-measurement is appended below.

## Re-measurement (01.11, `shell_syntax.py` at `eb2ebf9`)

After the lexer killers (`test_shell_lexer_killers.py`, PR #16) and the
command-arm killers (`test_shell_command_killers.py`):

| Module | Mutants | Killed | Annotated | Hung | Survived |
|---|---:|---:|---:|---:|---:|
| `shell_syntax.py` | 834 | 776 → 797 | 7 | 30 | 21 → 0 |

`tools/mutate.py --module shell_syntax` (test selection on, 90 s per mutant,
2 workers, 1667 s) reported 21 survivors clustered in the `case`-pattern
grouping of `_pipelines` and the `alias`/`trap`/`powershell` arms of
`command()`. Each was re-run against `test_shell_command_killers.py`: all 21
are now killed (every mutant's suite fails). The 7 annotated carry a
`# no mutate:` reason (index arithmetic whose boundary the quote scanner
already guarantees; an `Op` default read only on here-document operators). A
`TIMEOUT` is noticed by the run, not an open item. No unannotated survivor
remains.

## Re-measurement (01.11, `report.py` and `safety.py`)

| Module | Mutants | Killed | Annotated | Hung | Survived |
|---|---:|---:|---:|---:|---:|
| `report.py` | 285 | 249 | 36 | 0 | 0 |
| `safety.py` | 287 | 220 | 45 | 2 | 0 |

`tools/mutate.py --module` (test selection on, 90 s per mutant, 2 workers):
`report.py` 286 s, score 1.0; `safety.py` 441 s, score 0.991. The survivors
split into two groups. The genuine ones are killed by tests that exhibit the
behaviour directly (`test_safety_mutation_killers.py`): the executor breaks
out the instant output passes the limit even while the child holds the pipe
open, the kill signal of a timed-out probe is reaped as its exit code,
`_group_has_live_members` fails safe on an unreadable `/proc` and does not let
one bad entry abort the scan, and the private run directory creates missing
intermediates and reuses an existing private base. The rest are annotated with
their reason: the report-directory and baseline-scan guards are redundant with
`safe_read`'s `O_NOFOLLOW` and with the analysis-digest comparison, the read
bounds guard only a hostile file, and the output-directory type/owner check,
the pacing sleep and the exception label are defence-in-depth or TOCTOU guards
whose mutation changes no observed result. A `TIMEOUT` is not an open item.

The diff gate earned its place on its first pull request: the CV-1 fix
arrived with four surviving mutants on the new `mountinfo` read (bound
constants and the `read_gap` call) and was refused until two fixture tests
pinned the unreadable and the one-byte-over-the-bound cases.

Mutation score is a property of the test suite, not of the tool's detection
power (ASSURANCE.md, measurement contract).
