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

Mutation score is a property of the test suite, not of the tool's detection
power (ASSURANCE.md, measurement contract).
