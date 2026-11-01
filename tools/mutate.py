#!/usr/bin/env python3
"""Mutation testing for falsicore: does the suite notice when the code changes?

A mutant is the runtime package with one small, plausible fault inserted
(a comparison relaxed, a boolean flipped, a constant off by one, a return
value dropped, a call deleted). The suite "kills" it when at least one test
fails; a surviving mutant marks code whose behaviour no test pins down.
String literals are not mutated (messages are not behaviour).

The tool is standard-library only. It uses coverage.py's dynamic contexts,
when a coverage database with contexts is available, to run only the tests
that execute the mutated line; mutants on lines no test executes are
reported as NO_TESTS, the strongest signal of all. Every mutant runs in its
own copy of the tree with a regenerated SOURCE_MANIFEST, so the manifest
gate kills nothing by accident.

    python3 tools/mutate.py --diff origin/main        # mutants on changed lines only (PR gate)
    python3 tools/mutate.py --module detectors        # one module
    python3 tools/mutate.py --all --workers 4         # whole package (weekly)
    python3 tools/mutate.py --coverage               # record the per-test coverage contexts first

Exit status 1 when a mutant survives or has no tests, unless its line carries
`# no mutate: <reason>` (an equivalence or non-behaviour annotation that must
state its reason).
"""
from __future__ import annotations

import argparse
import ast
import copy
import json
import os
import queue
import re
import shutil
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "falsicore"
WORK = ROOT / ".mutation"               # ignored by the release manifest and git
COVERAGE_JSON = WORK / "coverage.json"
SCHEMA = "falsicore.mutation.v1"
NO_MUTATE = re.compile(r"#\s*no mutate:\s*\S")
COMPARE_SWAP = {ast.Lt: ast.LtE, ast.LtE: ast.Lt, ast.Gt: ast.GtE, ast.GtE: ast.Gt, ast.Eq: ast.NotEq,
                ast.NotEq: ast.Eq, ast.In: ast.NotIn, ast.NotIn: ast.In, ast.Is: ast.IsNot, ast.IsNot: ast.Is}
AUG_SWAP = {ast.Add: ast.Sub, ast.Sub: ast.Add, ast.Mult: ast.FloorDiv, ast.BitOr: ast.BitAnd, ast.BitAnd: ast.BitOr}


@dataclass
class Mutant:
    module: str
    line: int
    operator: str
    original: str
    mutated: str
    mutant_id: str
    status: str = "PENDING"        # KILLED | SURVIVED | NO_TESTS | TIMEOUT | ANNOTATED | ERROR
    tests: int = 0
    seconds: float = 0.0
    detail: str = ""
    scope: tuple[int, int] | None = None   # enclosing function's line span, for test selection


# ---- generation ---------------------------------------------------------------
class _Sites(ast.NodeVisitor):
    """Collect every node where an operator applies, with the enclosing function span."""

    def __init__(self) -> None:
        self.sites: list[tuple[ast.AST, str, list[ast.AST], tuple[int, int] | None]] = []
        self._scopes: list[tuple[int, int]] = []

    def _add(self, node: ast.AST, operator: str, replacements: list[ast.AST]) -> None:
        self.sites.append((node, operator, replacements, self._scopes[-1] if self._scopes else None))

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._scopes.append((node.lineno, getattr(node, "end_lineno", node.lineno)))
        self.generic_visit(node)
        self._scopes.pop()

    visit_AsyncFunctionDef = visit_FunctionDef  # type: ignore[assignment]

    def visit_Compare(self, node: ast.Compare) -> None:
        for index, op in enumerate(node.ops):
            swap = COMPARE_SWAP.get(type(op))
            if swap is not None:
                replacement = copy.deepcopy(node)
                replacement.ops[index] = swap()
                self._add(node, f"compare:{type(op).__name__}->{swap.__name__}", [replacement])
        self.generic_visit(node)

    def visit_BoolOp(self, node: ast.BoolOp) -> None:
        swapped = copy.deepcopy(node)
        swapped.op = ast.Or() if isinstance(node.op, ast.And) else ast.And()
        self._add(node, "boolop:swap", [swapped])
        self.generic_visit(node)

    def visit_UnaryOp(self, node: ast.UnaryOp) -> None:
        if isinstance(node.op, ast.Not):
            self._add(node, "not:remove", [copy.deepcopy(node.operand)])
        self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant) -> None:
        value = node.value
        if isinstance(value, bool):
            self._add(node, "bool:flip", [ast.Constant(value=not value)])
        elif isinstance(value, int) and not isinstance(value, bool):
            replacements = [ast.Constant(value=value + 1)]
            if value != 0:
                replacements.append(ast.Constant(value=0))
            self._add(node, "int:shift", replacements)

    def visit_Return(self, node: ast.Return) -> None:
        if node.value is not None and not (isinstance(node.value, ast.Constant) and node.value.value is None):
            self._add(node, "return:none", [ast.Return(value=ast.Constant(value=None))])
        self.generic_visit(node)

    def visit_Continue(self, node: ast.Continue) -> None:
        self._add(node, "continue->break", [ast.Break()])

    def visit_Break(self, node: ast.Break) -> None:
        self._add(node, "break->continue", [ast.Continue()])

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        swap = AUG_SWAP.get(type(node.op))
        if swap is not None:
            replacement = copy.deepcopy(node)
            replacement.op = swap()
            self._add(node, f"augassign:{type(node.op).__name__}->{swap.__name__}", [replacement])
        self.generic_visit(node)

    def visit_Expr(self, node: ast.Expr) -> None:
        if isinstance(node.value, ast.Call):
            self._add(node, "call:delete", [ast.Pass()])
        self.generic_visit(node)

    def visit_If(self, node: ast.If) -> None:
        negated = copy.deepcopy(node)
        negated.test = ast.UnaryOp(op=ast.Not(), operand=copy.deepcopy(node.test))
        self._add(node, "if:negate", [negated])
        self.generic_visit(node)


def _replace(tree: ast.Module, target: ast.AST, replacement: ast.AST) -> ast.Module:
    """A deep copy of `tree` with `target` (identified by position) replaced."""
    clone = copy.deepcopy(tree)
    key = (type(target).__name__, target.lineno, target.col_offset, getattr(target, "end_lineno", None),
           getattr(target, "end_col_offset", None))

    class Replacer(ast.NodeTransformer):
        done = False

        def visit(self, node: ast.AST) -> ast.AST:
            if (not self.done and hasattr(node, "lineno")
                    and (type(node).__name__, node.lineno, node.col_offset, getattr(node, "end_lineno", None),
                         getattr(node, "end_col_offset", None)) == key):
                self.done = True
                return ast.copy_location(replacement, node)
            return self.generic_visit(node)
    result = Replacer().visit(clone)
    ast.fix_missing_locations(result)
    return result


def generate(module: str, source: str, lines: set[int] | None = None) -> list[Mutant]:
    """Every mutant of `source`; restricted to `lines` when given. Annotated lines are kept but marked."""
    tree = ast.parse(source)
    source_lines = source.splitlines()
    sites = _Sites()
    sites.visit(tree)
    mutants: list[Mutant] = []
    counter: dict[int, int] = {}
    for node, operator, replacements, scope in sites.sites:
        line = getattr(node, "lineno", None)
        if line is None or (lines is not None and line not in lines):
            continue
        for replacement in replacements:
            mutated_tree = _replace(tree, node, replacement)
            mutated_source = ast.unparse(mutated_tree)
            counter[line] = counter.get(line, 0) + 1
            mutant = Mutant(module=module, line=line, operator=operator,
                            original=source_lines[line - 1].strip() if line - 1 < len(source_lines) else "",
                            mutated=ast.unparse(replacement).splitlines()[0][:160],
                            mutant_id=f"{module}:{line}:{counter[line]}:{operator}", scope=scope)
            if NO_MUTATE.search(mutant.original):
                mutant.status = "ANNOTATED"
                mutant.detail = mutant.original.split("# no mutate:", 1)[1].strip()
            mutant.detail = mutant.detail or mutated_source  # carries the full source until execution
            mutants.append(mutant)
    return mutants


# ---- test selection ----------------------------------------------------------------
def record_coverage_with_contexts(python: str = sys.executable) -> Path:
    """Run the suite once under coverage.py with per-test contexts; write COVERAGE_JSON."""
    WORK.mkdir(exist_ok=True)
    rcfile = WORK / "coveragerc"
    data = WORK / "coverage.data"
    rcfile.write_text(f"[run]\nbranch = true\nsource = falsicore\ndynamic_context = test_function\n"
                      f"data_file = {data}\n")
    try:
        rc = subprocess.run([python, "-m", "coverage", "run", f"--rcfile={rcfile}", "-m", "unittest", "discover",
                             "-s", "tests", "-q"], cwd=str(ROOT), timeout=1800).returncode
        if rc != 0:
            raise SystemExit("suite is not green; fix it before measuring mutants")
        subprocess.run([python, "-m", "coverage", "json", f"--rcfile={rcfile}", "--show-contexts",
                        "-o", str(COVERAGE_JSON)], cwd=str(ROOT), check=True, timeout=600)
    finally:
        rcfile.unlink(missing_ok=True)
        data.unlink(missing_ok=True)
    return COVERAGE_JSON


def covering_tests(coverage_json: Path, module: str) -> dict[int, set[str]] | None:
    """line -> unittest ids (tests.test_x.Class.test_y) that executed it, or None without data."""
    if not coverage_json.is_file():
        return None
    data = json.loads(coverage_json.read_text())
    for name, entry in data.get("files", {}).items():
        if Path(name).as_posix().endswith(f"falsicore/{module}.py"):
            table: dict[int, set[str]] = {}
            for line, contexts in entry.get("contexts", {}).items():
                ids = {c.split("|", 1)[0] for c in contexts if c}   # "" is import time, not a test
                table[int(line)] = ids
            return table
    return {}


def select_tests(table: dict[int, set[str]] | None, mutant: Mutant) -> set[str] | None:
    """Tests that executed the mutated line; a def line or a module constant falls back
    to the tests of the enclosing function, then to the whole suite (None)."""
    if table is None:
        return None
    direct = table.get(mutant.line, set())
    if direct:
        return direct
    if mutant.scope is not None:
        start, end = mutant.scope
        union: set[str] = set()
        for line in range(start, end + 1):
            union |= table.get(line, set())
        if union:
            return union
        return set()                      # a function no test executes: NO_TESTS
    return None                           # module level (constants, tables): whole suite


# ---- execution ----------------------------------------------------------------------
def _fresh_tree(destination: Path) -> None:
    shutil.copytree(ROOT, destination, symlinks=False,
                    ignore=shutil.ignore_patterns(".git", ".venv", "__pycache__", ".hypothesis", ".mypy_cache",
                                                  ".ruff_cache", ".falsicore-audit", ".coverage*", ".mutation"))


def run_mutant(mutant: Mutant, tests: set[str] | None, workdir: Path, python: str, timeout: float) -> Mutant:
    """Write the mutated module into a fresh tree copy and run the selected tests with fail-fast."""
    started = time.monotonic()
    if mutant.status == "ANNOTATED":
        return mutant
    if tests is not None and not tests:
        mutant.status, mutant.detail = "NO_TESTS", ""
        return mutant
    target = workdir / "falsicore" / f"{mutant.module}.py"
    original = target.read_text()
    try:
        target.write_text(mutant.detail + "\n")
        mutant.detail = ""
        # Test ids from coverage contexts are relative to tests/ (unittest discover -s tests).
        env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1", "FALSICORE_PBT_EXAMPLES": "30", "PYTHONPATH": "tests"}
        subprocess.run([python, "-B", "tools/build_release.py", "--write-manifest"], cwd=str(workdir), env=env,
                       capture_output=True, timeout=120)
        if tests:
            argv = [python, "-B", "-m", "unittest", "-f", "-q", *sorted(tests)]
            mutant.tests = len(tests)
        else:
            argv = [python, "-B", "-m", "unittest", "discover", "-s", "tests", "-q", "-f"]
            mutant.tests = -1   # whole suite (no selection data)
        try:
            proc = subprocess.run(argv, cwd=str(workdir), env=env, capture_output=True, text=True, timeout=timeout)
            if proc.returncode == 0:
                mutant.status = "SURVIVED"
            else:
                mutant.status = "KILLED"
                failing = re.findall(r"^(?:FAIL|ERROR): (\S+)", proc.stderr, re.M)
                mutant.detail = failing[0] if failing else proc.stderr.strip().splitlines()[-1][:160] if proc.stderr.strip() else ""
        except subprocess.TimeoutExpired:
            mutant.status, mutant.detail = "TIMEOUT", f"{timeout:.0f}s"
    except (OSError, SyntaxError) as exc:
        mutant.status, mutant.detail = "ERROR", type(exc).__name__
    finally:
        target.write_text(original)
        subprocess.run([python, "-B", "tools/build_release.py", "--write-manifest"], cwd=str(workdir),
                       capture_output=True, timeout=120)
    mutant.seconds = round(time.monotonic() - started, 2)
    return mutant


def changed_lines(base: str) -> dict[str, set[int]]:
    """module -> lines added/changed in falsicore/*.py since `base` (git diff -U0)."""
    git = shutil.which("git")
    if git is None:
        raise SystemExit("git is required for --diff")
    out = subprocess.run([git, "diff", "-U0", base, "--", "falsicore/"], cwd=str(ROOT), capture_output=True,
                         text=True, check=True).stdout
    return parse_diff(out)


def parse_diff(out: str) -> dict[str, set[int]]:
    """Added/changed line numbers per module from a unified diff with zero context."""
    result: dict[str, set[int]] = {}
    module = None
    for line in out.splitlines():
        if line.startswith("+++ "):
            module = None
            if line.startswith("+++ b/falsicore/") and line.endswith(".py"):
                module = line[len("+++ b/falsicore/"):-3]
                result.setdefault(module, set())
        elif line.startswith("@@") and module is not None:
            m = re.search(r"\+(\d+)(?:,(\d+))?", line)
            if m:
                start, count = int(m.group(1)), int(m.group(2) or "1")
                result[module].update(range(start, start + count))
    return {k: v for k, v in result.items() if v}


def run(modules: dict[str, set[int] | None], workers: int, timeout: float, python: str,
        coverage_json: Path, budget: float | None) -> dict:
    started = time.monotonic()
    mutants: list[Mutant] = []
    selection: dict[str, dict[int, set[str]] | None] = {}
    for module, lines in sorted(modules.items()):
        source = (PACKAGE / f"{module}.py").read_text()
        mutants.extend(generate(module, source, lines))
        selection[module] = covering_tests(coverage_json, module)
    with tempfile.TemporaryDirectory(prefix="falsicore-mutants-") as tmp:
        trees = [Path(tmp) / f"w{i}" for i in range(max(1, workers))]
        for tree in trees:
            _fresh_tree(tree)
        free: queue.Queue[Path] = queue.Queue()
        for tree in trees:
            free.put(tree)

        def work(mutant: Mutant) -> Mutant:
            if budget is not None and time.monotonic() - started > budget:
                mutant.status, mutant.detail = "NOT_RUN", "budget"
                return mutant
            tests = select_tests(selection[mutant.module], mutant)
            tree = free.get()           # a tree is held by exactly one running mutant
            try:
                return run_mutant(mutant, tests, tree, python, timeout)
            finally:
                free.put(tree)
        with ThreadPoolExecutor(max_workers=len(trees)) as pool:
            results = list(pool.map(work, mutants))
    counts: dict[str, int] = {}
    for m in results:
        counts[m.status] = counts.get(m.status, 0) + 1
    measured = sum(counts.get(k, 0) for k in ("KILLED", "SURVIVED", "NO_TESTS", "TIMEOUT"))
    score = counts.get("KILLED", 0) / measured if measured else None
    return {
        "schema": SCHEMA, "python": sys.version.split()[0], "wall_clock_seconds": round(time.monotonic() - started, 1),
        "per_mutant_timeout_seconds": timeout, "test_selection": coverage_json.is_file(),
        "operators": sorted({m.operator.split(":")[0] for m in results}),
        "modules": sorted(modules), "counts": counts, "mutation_score": None if score is None else round(score, 4),
        "mutants": [asdict(m) for m in results],
        "interpretation": "KILLED: a test failed. TIMEOUT: the suite hung (noticed, not open). SURVIVED: no test noticed. NO_TESTS: no test executes the line. "
                          "ANNOTATED: '# no mutate: <reason>' on the line. Survivors are candidates, not verdicts: "
                          "equivalence must be shown, not assumed.",
    }


def markdown(result: dict) -> str:
    lines = [f"# Mutation run — {', '.join(result['modules'])}", "",
             f"Counts: {result['counts']}; score {result['mutation_score']}; "
             f"test selection {'on' if result['test_selection'] else 'OFF (whole suite per mutant)'}; "
             f"{result['wall_clock_seconds']} s.", "",
             "| Mutant | Operator | Original | Mutated | Status | Tests | Detail |", "|---|---|---|---|---|---|---|"]
    for m in result["mutants"]:
        if m["status"] in ("KILLED",):
            continue
        lines.append(f"| `{m['mutant_id']}` | {m['operator']} | `{m['original'][:60]}` | `{m['mutated'][:60]}` | "
                     f"**{m['status']}** | {m['tests']} | {m['detail'][:80]} |")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    target = parser.add_mutually_exclusive_group()
    target.add_argument("--diff", metavar="BASE", help="mutate only lines changed since BASE (git ref)")
    target.add_argument("--module", action="append", help="mutate this module (repeatable)")
    target.add_argument("--all", action="store_true", help="mutate every runtime module")
    parser.add_argument("--coverage", action="store_true", help="record per-test coverage contexts, then exit")
    parser.add_argument("--workers", type=int, default=2)
    parser.add_argument("--timeout", type=float, default=180.0, help="seconds per mutant")
    parser.add_argument("--budget", type=float, help="stop starting mutants after this many seconds")
    parser.add_argument("--json", type=Path, help="write the result here")
    parser.add_argument("--markdown", type=Path, help="write the survivor table here")
    parser.add_argument("--allow-survivors", action="store_true", help="exit 0 even when mutants survive")
    args = parser.parse_args(argv)
    if args.coverage:
        record_coverage_with_contexts()
        print(f"coverage contexts written to {COVERAGE_JSON.relative_to(ROOT)}")
        return 0
    if args.diff:
        modules: dict[str, set[int] | None] = dict(changed_lines(args.diff))
        if not modules:
            print("no changed lines in falsicore/: nothing to mutate")
            return 0
    elif args.module:
        modules = {m: None for m in args.module}
    elif args.all:
        modules = {p.stem: None for p in sorted(PACKAGE.glob("*.py")) if p.stem != "__init__"}
    else:
        parser.error("one of --diff, --module, --all, --coverage is required")
    if not COVERAGE_JSON.is_file():
        print("no coverage contexts (.mutation/coverage.json): running the whole suite per mutant; "
              "use --coverage first for test selection", file=sys.stderr)
    result = run(modules, args.workers, args.timeout, sys.executable, COVERAGE_JSON, args.budget)
    encoded = json.dumps(result, indent=2, ensure_ascii=False) + "\n"
    if args.json:
        args.json.write_text(encoded)
    if args.markdown:
        args.markdown.write_text(markdown(result))
    print(markdown(result), end="")
    # A mutant that hangs the suite was noticed (the run did not finish): it is
    # reported but is not an open item. Survivors, untested lines and errors are.
    open_items = sum(result["counts"].get(k, 0) for k in ("SURVIVED", "NO_TESTS", "ERROR"))
    return 0 if args.allow_survivors or open_items == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
