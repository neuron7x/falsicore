# FALSICORE — формальний акт незалежної технічної верифікації

**Audit ID:** `FALSICORE-VA-2026-11-01`  
**Status:** `RELEASE-ASSURANCE HOLD` (не означає заборони всіх experimental builds)  
**Repository:** https://github.com/neuron7x/falsicore  
**Audited commit:** `41745142378ccab363974db9f3cd568188706524`  
**Date:** 2026-11-01  
**Evidence scope:** code review of security-critical paths, original GitHub review threads, observed CI logs, tag/release metadata, current reference standards.

## 0. Епістемічний контракт

- `SC` — source-confirmed: код реалізує умову, що логічно суперечить заявленому контракту. Це **не** синонім успішно відтвореного повного repo test.
- `RR` — review-reproduced: у GitHub review наведено відтворений контрприклад, незалежно повторно на HEAD не виконувався.
- `EG` — evidence gap: належного доказу немає; це не доказ дефектності продукту.
- `FX` — історичний дефект має виправлення у поточному source; formal proof of complete behavior still bounded.
- `NOT_RUN`, `SKIPPED`, `PARTIAL`, `INCONCLUSIVE`, `ANNOTATED` **не є PASS**. Зелений workflow сам собою підтверджує лише виконання власного workflow contract.
- Аудит не є сертифікацією NIST/OpenSSF/SLSA, не доводить відсутність невідомих уразливостей, а також не доводить detection efficacy на реальних malware.

**Data:** 102 файли в Git tree, 28 GitHub review threads (27 unresolved, 1 resolved); 4 з 27 unresolved мають фактичне виправлення в source, 23 залишаються предметом доведення. Окремо виявлено 16 інших дефектів або відсутніх доказів. **Загалом 39 позицій; 4 історично усунені наведені окремо.**

**Current CI:** [verify run](https://github.com/neuron7x/falsicore/actions/runs/41272761288) PASS; 906 тестів у Python 3.13 (2 skipped), ~93% coverage у static-analysis job; [CodeQL](https://github.com/neuron7x/falsicore/actions/runs/41272761349) PASS. GitHub release v0.2.0 веде на commit 70ed7107, який на 6 commits позаду HEAD; GitHub tag verification повертає `verified=false / unknown_key`.

## 1. Реєстр усіх встановлених позицій

Кожен пункт містить сценарій, наслідок, мінімальне операційне спростування та точну URL-підставу. Якщо review був написаний для старішого PR, це явно обмежується класом `SC+RR`: джерело у поточному code path зіставлено, але повний тест не запускався незалежно.

### FC-01 · P1 · Nested process-substitution loses context

**Class:** `SC+RR` | **Area:** `shell` | **Status:** `REQUIRES_CLOSURE`  
**Mechanism:** Вкладене аналізування маркера PROCSUB може звернутися до відсутнього елемента procsubs і спричинити IndexError, після якого persistence collector відкачується.  
**Falsifier / acceptance test:** Fixtures для eval sh <(...) і eval source <(...) не піднімають exception; повертають коректну класифікацію або explicit limitation; жодні інші знахідки не втрачені.  
**Evidence:** [falsicore/shell_syntax.py](https://github.com/neuron7x/falsicore/pull/4#discussion_r4433416582).

### FC-02 · P2 · Command substitution taint is aggregated across unrelated words

**Class:** `SC+RR` | **Area:** `shell` | **Status:** `REQUIRES_CLOSURE`  
**Mechanism:** Код збирає sub_emits з усіх word, а потім трактує результат як джерело виконуваного операнда; нешкідливий аргумент може породити REMOTE_SCRIPT_PIPELINE.  
**Falsifier / acceptance test:** Pair fixtures: downloaded data only as argv -> no executable-code finding; downloaded code in -c/eval -> finding; labels scoped to exact operand.  
**Evidence:** [falsicore/shell_syntax.py](https://github.com/neuron7x/falsicore/pull/4#discussion_r4433416597).

### FC-03 · P2 · Here-string misclassified as network redirection

**Class:** `SC+RR` | **Area:** `shell` | **Status:** `REQUIRES_CLOSURE`  
**Mechanism:** Для кожного redirect не перевіряється оператор; <<< /dev/tcp/.. є даними, не відкриттям сокета.  
**Falsifier / acceptance test:** cat <<< /dev/tcp/example/80 -> no NETWORK_REDIRECTION; exec 3<>/dev/tcp/example/80 -> positive.  
**Evidence:** [falsicore/shell_syntax.py](https://github.com/neuron7x/falsicore/pull/4#discussion_r4433416600).

### FC-04 · P2 · HOME-relative source path with double slash escapes base

**Class:** `SC+RR` | **Area:** `shell` | **Status:** `REQUIRES_CLOSURE`  
**Mechanism:** self.home / target[len(prefix):] скидає базу, якщо суфікс починається /.  
**Falsifier / acceptance test:** Fixtures $HOME//.bash_aliases, ~//.bash_aliases, звичайний шлях, symlink, offline root; тільки шлях усередині target home використовується.  
**Evidence:** [falsicore/collectors.py](https://github.com/neuron7x/falsicore/pull/5#discussion_r4433436330).

### FC-05 · P1 · Eval-site qualification uses aggregate counts

**Class:** `SC+RR` | **Area:** `trust` | **Status:** `REQUIRES_CLOSURE`  
**Mechanism:** _shell_limit порівнює загальні unresolved_expansions і len(evaluated_programs), тому невідоме джерело може бути зараховано довіреним іншою підстановкою.  
**Falsifier / acceptance test:** Mixed eval із packaged $(dircolors) + $hook та multiple eval-sites -> PARSE_UNSUPPORTED, ніколи COMPLETED лише через арифметику лічильників.  
**Evidence:** [falsicore/collectors.py](https://github.com/neuron7x/falsicore/pull/14#discussion_r4434047820).

### FC-06 · P2 · Relative executable name aliases packaged executable

**Class:** `SC+RR` | **Area:** `trust` | **Status:** `REQUIRES_CLOSURE`  
**Mechanism:** PurePosixPath(name).name перетворює ./dircolors на dircolors і підставляє системний executable замість фактичного.  
**Falsifier / acceptance test:** ./prog, ../prog, path/to/prog ніколи не отримують package attestation за basename; тільки точно встановлена канонічна ціль.  
**Evidence:** [falsicore/collectors.py](https://github.com/neuron7x/falsicore/pull/14#discussion_r4434047821).

### FC-07 · P1 · Relay-program denylist is not sound

**Class:** `SC+RR` | **Area:** `trust` | **Status:** `REQUIRES_CLOSURE`  
**Mechanism:** dd відсутній у RELAY_PROGRAMS; пакетний digest самої програми не засвідчує дані, що вона видає.  
**Falsifier / acceptance test:** eval of output copied from arbitrary file via dd/other relay -> PARSE_UNSUPPORTED; proof cases with trusted program whose output is not input.  
**Evidence:** [falsicore/collectors.py](https://github.com/neuron7x/falsicore/pull/14#discussion_r4434047822).

### FC-08 · P1 · Nested command substitutions inside ${...} discarded

**Class:** `SC+RR` | **Area:** `shell` | **Status:** `REQUIRES_CLOSURE`  
**Mechanism:** _dollar склеює складний parameter expansion у marker VAR:? без subcommands; виконувана підстановка може зникнути і з findings, і з limitations.  
**Falsifier / acceptance test:** Nested ${var:-$(...)} variants recognized or explicit UNPARSED/UNSUPPORTED limitation; no clean acceptance of unexamined executable syntax.  
**Evidence:** [falsicore/shell_syntax.py](https://github.com/neuron7x/falsicore/pull/16#discussion_r4434173031).

### FC-09 · P2 · Unbounded recursive quote/parameter parser

**Class:** `SC+RR` | **Area:** `shell` | **Status:** `REQUIRES_CLOSURE`  
**Mechanism:** _double_quote_end і _balanced рекурсивно викликаються до загального MAX_DEPTH аналізатора; глибокі inputs піднімають RecursionError.  
**Falsifier / acceptance test:** Nested quoted expansions at 500+ levels give bounded NESTING_LIMIT/UNPARSED_QUOTING, no exception, bounded CPU/RSS and per-file incompleteness.  
**Evidence:** [falsicore/shell_syntax.py](https://github.com/neuron7x/falsicore/pull/16#discussion_r4434173036).

### FC-10 · P2 · hidepid mount visibility incorrectly treated as kernel hiding

**Class:** `SC+RR` | **Area:** `crossview` | **Status:** `REQUIRES_CLOSURE`  
**Mechanism:** EPERM у kill(pid,0) означає існування, але hidepid=2 легітимно приховує /proc іншого користувача.  
**Falsifier / acceptance test:** hidepid=0/1/2 and same/foreign UID fixtures; restricted view -> scope limitation, not HIDDEN_PROCESS.  
**Evidence:** [falsicore/collectors.py](https://github.com/neuron7x/falsicore/pull/7#discussion_r4433565374).

### FC-11 · P2 · Transient sockets create NETLINK_ONLY false alarm

**Class:** `SC+RR` | **Area:** `crossview` | **Status:** `REQUIRES_CLOSURE`  
**Mechanism:** netlink_only = netlink - before - after спрацьовує саме для короткоживучого сокета між snapshot-ами.  
**Falsifier / acceptance test:** Transient UDP churn -> no high-severity hidden-listener finding; stable discrepancy survives independently repeated confirmation.  
**Evidence:** [falsicore/collectors.py](https://github.com/neuron7x/falsicore/pull/7#discussion_r4433565378).

### FC-12 · P2 · Partial ss output used for negative inference

**Class:** `SC+RR` | **Area:** `crossview` | **Status:** `REQUIRES_CLOSURE`  
**Mechanism:** Статус PARTIAL приймається як повна таблиця, попри truncation; стабільні procfs listeners оголошуються прихованими.  
**Falsifier / acceptance test:** Command PARTIAL with truncated empty ss result -> PARTIAL coverage, no absence-based hidden listener; exact command gap recorded.  
**Evidence:** [falsicore/collectors.py](https://github.com/neuron7x/falsicore/pull/7#discussion_r4433565383).

### FC-13 · P2 · Listener identity collapses address and network family

**Class:** `SC+RR` | **Area:** `crossview` | **Status:** `REQUIRES_CLOSURE`  
**Mechanism:** Набір (proto,port) не відрізняє 127.0.0.1:8080 від 127.0.0.2:8080 або IPv4 від IPv6.  
**Falsifier / acceptance test:** Distinct interface/address/family fixtures remain distinct; exact local endpoint identity used in both views with privacy-safe hashing if stored.  
**Evidence:** [falsicore/collectors.py](https://github.com/neuron7x/falsicore/pull/7#discussion_r4433565385).

### FC-14 · P2 · Offline RPM scope limit suppresses unrelated package failure

**Class:** `SC+RR` | **Area:** `offline` | **Status:** `REQUIRES_CLOSURE`  
**Mechanism:** Essential checks видаляються за будь-якою ознакою LIVE_ONLY_NOT_IN_OFFLINE_IMAGE, навіть якщо той самий collector має реальні disk-reading gaps.  
**Falsifier / acceptance test:** Offline RPM image with unreadable/symlinked repo config -> INCONCLUSIVE; виключаються тільки повністю SKIPPED live-only collector-и.  
**Evidence:** [falsicore/detectors.py](https://github.com/neuron7x/falsicore/pull/9#discussion_r4433644335).

### FC-15 · P2 · Unreadable/over-budget dpkg metadata silently dropped

**Class:** `SC+RR` | **Area:** `offline` | **Status:** `REQUIRES_CLOSURE`  
**Mechanism:** _dpkg_md5 пропускає unreadable >4MiB *.md5sums і caps, після чого верифікація порожнього індексу може завершитися COMPLETED.  
**Falsifier / acceptance test:** Files >4MiB, total >128MiB, >20k records, malformed/permission -> explicit incomplete; records omitted measured separately.  
**Evidence:** [falsicore/collectors.py](https://github.com/neuron7x/falsicore/pull/9#discussion_r4433644338).

### FC-16 · P2 · Offline journal parent symlink crosses root boundary

**Class:** `SC+RR` | **Area:** `offline` | **Status:** `REQUIRES_CLOSURE`  
**Mechanism:** _journal перевіряє лише final directory; journalctl --directory може перейти через ancestor symlink у live host.  
**Falsifier / acceptance test:** Ancestor symlink under root must be refused; no host-journal leaks; TOCTOU-safe directory handling or skip with limitation.  
**Evidence:** [falsicore/collectors.py](https://github.com/neuron7x/falsicore/pull/9#discussion_r4433644340).

### FC-17 · P2 · AST unparse causes false mutant kills

**Class:** `SC+RR` | **Area:** `mutation` | **Status:** `REQUIRES_CLOSURE`  
**Mechanism:** Переформатування незмінених фрагментів змінює лапки, що ламає source-regex тести, і може створити KILLED без перевірки мутації.  
**Falsifier / acceptance test:** No-op AST roundtrip must not fail suite; mutate only original source span or semantic tests must ignore formatting; mutation tester self-tests.  
**Evidence:** [tools/mutate.py](https://github.com/neuron7x/falsicore/pull/10#discussion_r4433773026).

### FC-18 · P2 · Continuation-line operator modifications omitted from diff mutations

**Class:** `SC+RR` | **Area:** `mutation` | **Status:** `REQUIRES_CLOSURE`  
**Mechanism:** Відбір лише за node.lineno пропускає оператор на іншому рядку багаторядкового вузла.  
**Falsifier / acceptance test:** Mutation of and→or on changed continuation line always yields eligible mutant; 0 selected on modified semantic code -> FAIL.  
**Evidence:** [tools/mutate.py](https://github.com/neuron7x/falsicore/pull/10#discussion_r4433773027).

### FC-19 · P2 · Mutation budget expiry returns success with NOT_RUN

**Class:** `SC+RR` | **Area:** `mutation` | **Status:** `REQUIRES_CLOSURE`  
**Mechanism:** Exit logic рахує SURVIVED, NO_TESTS, ERROR, але не NOT_RUN.  
**Falsifier / acceptance test:** tools/mutate.py --module detectors --budget 0 exits nonzero when any NOT_RUN; test verify --allow-survivors never masquerades as full coverage.  
**Evidence:** [tools/mutate.py](https://github.com/neuron7x/falsicore/pull/10#discussion_r4433773030).

### FC-20 · P2 · Package metadata version inconsistent with runtime

**Class:** `SC` | **Area:** `release` | **Status:** `REQUIRES_CLOSURE`  
**Mechanism:** pyproject [project].version=0.1.3 while falsicore.__version__=0.2.0.  
**Falsifier / acceptance test:** Runtime version == wheel/SDist metadata == release tag == asset label; single version SSOT tested.  
**Evidence:** [pyproject.toml](https://github.com/neuron7x/falsicore/pull/11#discussion_r4433814849).

### FC-21 · P2 · Evidence freshness accepts stale counts and coverage

**Class:** `SC` | **Area:** `evidence` | **Status:** `REQUIRES_CLOSURE`  
**Mechanism:** --check порівнює schema/version/suite exit лише; does not bind test inputs or measured coverage.  
**Falsifier / acceptance test:** Tamper suite.ran, test_files, coverage, SHA and suite exit -> --check FAIL unless all exact measurements and source digest validated.  
**Evidence:** [tools/release_evidence.py](https://github.com/neuron7x/falsicore/pull/11#discussion_r4433814852).

### FC-22 · P2 · Evidence regeneration poisoned by self-referential test

**Class:** `SC+RR` | **Area:** `evidence` | **Status:** `REQUIRES_CLOSURE`  
**Mechanism:** unittest suite перевіряє existing RELEASE_EVIDENCE --check while generator itself runs suite to write a fresh file.  
**Falsifier / acceptance test:** Start from stale/red evidence, run controlled regenerate -> green once true implementation gates pass, without manual JSON editing.  
**Evidence:** [tests/test_release_evidence_tool.py](https://github.com/neuron7x/falsicore/pull/12#discussion_r4433876422).

### FC-23 · P2 · Line-wide #no mutate hides behavior-changing mutants

**Class:** `SC+RR` | **Area:** `mutation` | **Status:** `REQUIRES_CLOSURE`  
**Mechanism:** Any mutation on annotated line becomes ANNOTATED; os.read(fd,0) suppresses observable output, so it is not equivalent.  
**Falsifier / acceptance test:** Only exact proven-equivalent mutation IDs may be waived; 65536→0 mutation must be executed and killed by child stdout capture test.  
**Evidence:** [tools/mutate.py](https://github.com/neuron7x/falsicore/pull/18#discussion_r4434374781).

### FC-24 · P1 · Evidence generator success ignores failing ancillary measurements

**Class:** `SC` | **Area:** `evidence` | **Status:** `REQUIRES_CLOSURE`  
**Mechanism:** measure() stores exits from Ruff/Bandit/mypy/validity, but main() returns exit based solely on suite.exit.  
**Falsifier / acceptance test:** Inject static_analysis.detection_validity.exit=1 with suite.exit=0 -> generator and --check nonzero; all required fields and inputs verified.  
**Evidence:** [tools/release_evidence.py](https://github.com/neuron7x/falsicore/blob/41745142378ccab363974db9f3cd568188706524/tools/release_evidence.py#L136).

### FC-25 · P1 · Tag release job permits skipping property tests

**Class:** `SC` | **Area:** `release` | **Status:** `REQUIRES_CLOSURE`  
**Mechanism:** release.yml does not install Hypothesis and does not set FALSICORE_REQUIRE_HYPOTHESIS=1; property-test classes skip when missing.  
**Falsifier / acceptance test:** Tag pipeline installs pinned PBT dependency and fails if PBT absent, skipped or red; same HEAD passes required static, validity, mutation and CodeQL gates.  
**Evidence:** [.github/workflows/release.yml](https://github.com/neuron7x/falsicore/blob/41745142378ccab363974db9f3cd568188706524/.github/workflows/release.yml#L24).

### FC-26 · P2 · Published tag trails main by six commits under same runtime version

**Class:** `SC` | **Area:** `release` | **Status:** `REQUIRES_CLOSURE`  
**Mechanism:** v0.2.0 tag = 70ed7107, main = 41745142, ahead_by = 6; functionality and tests changed without release version update.  
**Falsifier / acceptance test:** Release identity defined by immutable commit; new version and tag for changed artifacts; no false parity assertion between main and published asset.  
**Evidence:** [falsicore/__init__.py](https://github.com/neuron7x/falsicore/compare/70ed7107bcd6c43a66b4e4cb59db25ee1b3a8516...41745142378ccab363974db9f3cd568188706524).

### FC-27 · P2 · GitHub cannot verify SSH tag signature

**Class:** `SC` | **Area:** `provenance` | **Status:** `REQUIRES_CLOSURE`  
**Mechanism:** Annotated tag exists but GitHub API returns verified=false reason=unknown_key; it does not prove a forged tag.  
**Falsifier / acceptance test:** Verify signing public key through independent trusted identity channel; repository GitHub Verified or equivalent trust-root proof; sign release manifest/attestation.  
**Evidence:** [v0.2.0](https://github.com/neuron7x/falsicore/releases/tag/v0.2.0).

### FC-28 · P1 · Default branch lacks branch protection/rulesets

**Class:** `SC` | **Area:** `governance` | **Status:** `REQUIRES_CLOSURE`  
**Mechanism:** GitHub branches/main protected=false and repository rulesets endpoint returns []; direct changes are not blocked by these controls.  
**Falsifier / acceptance test:** Main protection/rulesets enforced; direct push rejected, required exact-head CI before merge; solo maintainer does not need separate human approval.  
**Evidence:** [.github/workflows/verify.yml](https://github.com/neuron7x/falsicore/settings/branches).

### FC-29 · P2 · Whole-package scheduled job accepts survivors by design

**Class:** `SC` | **Area:** `mutation` | **Status:** `REQUIRES_CLOSURE`  
**Mechanism:** --allow-survivors makes successful job outcome a measurement receipt, not mutation-quality closure; table is partial and historical.  
**Falsifier / acceptance test:** Publish complete per-module mutation receipts bound to HEAD and treat unmeasured critical-path mutants as NOT_ESTABLISHED; strict release gate blocks unresolved non-equivalent critical mutants.  
**Evidence:** [.github/workflows/mutation.yml](https://github.com/neuron7x/falsicore/blob/41745142378ccab363974db9f3cd568188706524/.github/workflows/mutation.yml#L24).

### FC-30 · P2 · Pacman mtree index silently discards incomplete database

**Class:** `SC` | **Area:** `offline` | **Status:** `REQUIRES_CLOSURE`  
**Mechanism:** _pacman_records drops bad/oversized mtree and record/byte cap without passing incompleteness to verification.  
**Falsifier / acceptance test:** Malformed, unreadable, >cap pacman mtree fixtures -> PARTIAL, exact missing-record counters; no COMPLETED with incomplete reference set.  
**Evidence:** [falsicore/collectors.py](https://github.com/neuron7x/falsicore/blob/41745142378ccab363974db9f3cd568188706524/falsicore/collectors.py#L1057).

### FC-31 · P1-EG · No representative real-malware corpus validation

**Class:** `EG` | **Area:** `field` | **Status:** `REQUIRES_CLOSURE`  
**Mechanism:** docs/RELEASE_EVIDENCE explicitly lists malware-corpus validation under not_performed.  
**Falsifier / acceptance test:** Pre-registered corpus with confirmed labels, provenance, holdout split, environment coverage and per-rule TPR/FNR with confidence intervals.  
**Evidence:** [docs/RELEASE_EVIDENCE.json](https://github.com/neuron7x/falsicore/blob/41745142378ccab363974db9f3cd568188706524/docs/RELEASE_EVIDENCE.json).

### FC-32 · P1-EG · Field false-alarm rate, precision and time to detection unknown

**Class:** `EG` | **Area:** `field` | **Status:** `REQUIRES_CLOSURE`  
**Mechanism:** 57 positive and 27 benign-twin synthetic scenarios cannot establish field prevalence-conditioned precision or operational error costs.  
**Falsifier / acceptance test:** Independent benign/malicious host-day corpus: measure FPR per host-day, TPR, PPV by base-rate scenario, detection delay, CIs and subgroup shift.  
**Evidence:** [docs/DETECTION_VALIDITY.json](https://github.com/neuron7x/falsicore/blob/41745142378ccab363974db9f3cd568188706524/docs/DETECTION_VALIDITY.json).

### FC-33 · P2-EG · No measured privileged system-scope host scan

**Class:** `EG` | **Area:** `environment` | **Status:** `REQUIRES_CLOSURE`  
**Mechanism:** Explicitly listed in not_performed, and simulator coverage cannot replace real kernel permission behavior.  
**Falsifier / acceptance test:** Isolated disposable Linux VM privileged scan + command audit proving read-only behavior, bounded subprocess lifecycle, accurate coverage.  
**Evidence:** [docs/RELEASE_EVIDENCE.json](https://github.com/neuron7x/falsicore/blob/41745142378ccab363974db9f3cd568188706524/docs/RELEASE_EVIDENCE.json).

### FC-34 · P2-EG · No real mounted offline image evidence

**Class:** `EG` | **Area:** `environment` | **Status:** `REQUIRES_CLOSURE`  
**Mechanism:** Offline tested only on constructed fixture images; real-image acquisition/provenance verification not measured.  
**Falsifier / acceptance test:** Read-only mounted forensic image with known ground truth and independent image hash, absolute-path containment proof, verified provenance log.  
**Evidence:** [docs/RELEASE_EVIDENCE.json](https://github.com/neuron7x/falsicore/blob/41745142378ccab363974db9f3cd568188706524/docs/RELEASE_EVIDENCE.json).

### FC-35 · P2-EG · Cross-platform reproducible build not established

**Class:** `EG` | **Area:** `release` | **Status:** `REQUIRES_CLOSURE`  
**Mechanism:** Two identical ZIP/pyz builds on the same platform do not prove equivalence across interpreters and runners.  
**Falsifier / acceptance test:** Independent runners for target matrix produce defined identical bytes or documented platform-specific reproducibility contracts and manifest parity.  
**Evidence:** [docs/VERIFICATION.md](https://github.com/neuron7x/falsicore/blob/41745142378ccab363974db9f3cd568188706524/docs/VERIFICATION.md).

### FC-36 · P2-EG · Independent external implementation review not demonstrated

**Class:** `EG` | **Area:** `assurance` | **Status:** `REQUIRES_CLOSURE`  
**Mechanism:** Project acknowledges non-independent same-family review; cannot assert external certification.  
**Falsifier / acceptance test:** Independent challenge audit against frozen commit, seeded defects and evidence receipts; no mandatory separate human sign-off in solo gate.  
**Evidence:** [docs/AUDIT.md](https://github.com/neuron7x/falsicore/blob/41745142378ccab363974db9f3cd568188706524/docs/AUDIT.md).

### FC-37 · P2-EG · Release assets lack demonstrated signed build attestation and SBOM

**Class:** `EG` | **Area:** `provenance` | **Status:** `REQUIRES_CLOSURE`  
**Mechanism:** Published release shows 4 assets: full.zip/sha256 and pyz/sha256; plain hashes alone are not independent author/build provenance.  
**Falsifier / acceptance test:** Artifact SHA256 bound to signed provenance with source commit, builder identity and dependencies; verifiable by external consumer; SBOM published where applicable.  
**Evidence:** [release/assets](https://github.com/neuron7x/falsicore/releases/tag/v0.2.0).

### FC-38 · P1 · Release evidence has no exact source/test fingerprint

**Class:** `SC` | **Area:** `evidence` | **Status:** `REQUIRES_CLOSURE`  
**Mechanism:** RELEASE_EVIDENCE.json includes version and date, no HEAD commit SHA or source/test Merkle digest; --check cannot detect same-version drift.  
**Falsifier / acceptance test:** Attestation exact HEAD, source tree, test inventory, toolchain and command inputs; any single changed input forces invalidation/re-measurement.  
**Evidence:** [docs/RELEASE_EVIDENCE.json](https://github.com/neuron7x/falsicore/blob/41745142378ccab363974db9f3cd568188706524/docs/RELEASE_EVIDENCE.json).

### FC-39 · P2-EG · Private vulnerability disclosure configuration not confirmed

**Class:** `EG` | **Area:** `governance` | **Status:** `REQUIRES_CLOSURE`  
**Mechanism:** SECURITY.md requests enabling private vulnerability reporting; actual repo configuration could not be verified with available endpoint.  
**Falsifier / acceptance test:** Confirm active private vulnerability reporting via permitted read-only GitHub configuration/maintainer evidence; publish non-sensitive response policy.  
**Evidence:** [SECURITY.md](https://github.com/neuron7x/falsicore/blob/41745142378ccab363974db9f3cd568188706524/SECURITY.md).

## 2. Historical review items fixed in current source

These four are **not counted as active defects**; review conversation status does not supersede actual source evidence.

| Review | Historical problem | Fix in current code | Evidence |
|---|---|---|---|

| PR #2 | Hypothesis-absent NameError | tests/test_properties.py: if HAVE_HYPOTHESIS guards class definitions | [source review](https://github.com/neuron7x/falsicore/pull/2#discussion_r4433362441) |

| PR #4 | Offline image home resolved from live NSS | Audit._image_passwd uses root and image passwd | [source review](https://github.com/neuron7x/falsicore/pull/4#discussion_r4433416587) |

| PR #6 | Package parsers not wired into collector | Current Audit.packages routes dpkg, rpm, pacman, apk | [source review](https://github.com/neuron7x/falsicore/pull/6#discussion_r4433480865) |

| PR #7 | /proc/self symlink inhibits live collector | Current Audit._proc_self uses own numeric PID | [source review](https://github.com/neuron7x/falsicore/pull/7#discussion_r4433565372) |


## 3. Формальна модель верифікації

### 3.1. Три незалежні твердження

1. **Implementation correctness**: в межах оголошеної семантики код реалізує специфікацію. Спостерігається через precise regression, property-based, fault injection, mutation testing. Це *verification*.
2. **Measurement correctness**: вимірювальні та release tools правдиво повідомляють зміни коду, покриття, skipped/partial/not-run і provenance. Це *assurance of evidence*, не синонім тестів реалізації.
3. **Operational detection validity**: система виявляє ті явища в реальній цільовій популяції, про які робить практичні твердження; оцінюється незалежними ground-truth dataset, false alarm rate, missed-detection rate, попереднім визначенням сценаріїв та меж OOD. Це *validation*.

### 3.2. Інваріанти

- `INV-1 / FAIL-CLOSED:` якщо спостереження необхідне для негативного висновку і воно неповне, verdict не може бути `NO_COMPROMISE_INDICATORS_OBSERVED` без чіткої зміни оголошеного scope.
- `INV-2 / NO TRUST FROM BASENAME:` довіра не переноситься з одного executable на інший лише за однаковою базовою назвою. Подібно, `package DB digest` не є підтвердженням довіри до самої бази.
- `INV-3 / TAINT PROVENANCE:` джерело downloaded/decoded code прикріплюється до фактичного виконуваного операнда, а не до будь-якого аргументу процесу.
- `INV-4 / TEMPORAL CONSISTENCY:` crossview negative-space comparison допустимий тільки за порівнянних часових і просторових спостережень; `PARTIAL` і kernel policies блокують сильну інференцію.
- `INV-5 / ROOT CONTAINMENT:` жодне офлайнове спостереження або subprocess path не може читати live host поза оголошеним root; TOCTOU має або контролюватися, або ставати named limitation.
- `INV-6 / INDEPENDENT EVIDENCE:` приймальний gate не повинен покладатися на самодекларацію stale artifacts, а його PASS має бути виміряний на точному commit SHA та provenance зв'язаному з artifact SHA-256.
- `INV-7 / EXPLICIT INCOMPLETENESS:` mutation counts `NOT_RUN`, `NO_TESTS`, `SURVIVED`, non-equivalent `ANNOTATED`, source audit exceptions, nonzero static check -> FAIL/INCONCLUSIVE, не PASS.
- `INV-8 / SCOPE-BOUNDED CLAIMS:` відсутність знайдених індикаторів ніколи не виводить машинної чистоти; `reproducible` в одній платформі не означає cross-platform equivalence; synthetic recall не є field recall.

### 3.3. Математична структура

Нехай `C` — множина essential checks заданого режиму, `E(c)` — доведена повнота observation в оголошеному scope, `R(c)` — статус, `F` — релевантний detection finding, `T` — trusted measurement trace.

```
FOR ALL c in C:
    R(c) == COMPLETED  ==> E(c) == TRUE
    NOT E(c) and not F ==> verdict != NO_COMPROMISE_INDICATORS_OBSERVED

release_assurance =
    implementation_gate AND collection_gate AND measurement_gate
    AND supply_chain_gate AND domain_validation_gate
```

Справжня `E(c)` не може бути доведена поза явно заданим observable scope; для compromised kernel цей scope взагалі може бути ненадійним. Це не привід фальшиво оголошувати COMPLETE.

Для польової ефективності потрібні `TP, FP, TN, FN` на незалежній популяції, `TPR = TP/(TP+FN)`, `FPR = FP/(FP+TN)` і залежний від prevalence позитивний predictive value:

```
PPV = (TPR * prevalence) /
      ((TPR * prevalence) + (FPR * (1 - prevalence)))
```

`57/57` synthetic detected та `0/27` benign-twin alarms **не можуть бути перенесені на реальні інциденти**. Навіть якщо умовно припустити незалежну випадкову вибірку (чого цей fixture harness не забезпечує), одностороння верхня 95% межа FPR для 0/27 ≈ 10.5%. Тому `0/27` не означає `FPR=0` у полі.

## 4. Acceptance gate specification

**Outcome enum:** `PASS | FAIL | INCONCLUSIVE | NOT_RUN`. Gates all apply to same pinned HEAD; false truthy values, stale evidence, skipped checks are blocked.

| Gate | Scope | Required refutation work | Required evidence |
|---|---|---|---|
| G0 | Exact HEAD, release identity | FC-20, 21, 24, 25, 26, 27, 28, 38; fail tag/test/provenance mismatch | commit SHA, GitHub API receipt, tag verification, version equality, signed provenance |
| G1 | Shell and eval soundness | FC-01..09; positive/benign/unknown triplets, precise per-op taint, bounded parser, anti-alias | fixtures, PBT, canary mutation killer, no silent COMPLETE |
| G2 | Crossview soundness | FC-10..13; stable address-aware compares, untrusted partial data refusal, hidepid and ephemeral socket tests | two-view trace, environment facts, rejection scenarios |
| G3 | Offline forensics | FC-14..16, 30; no ancestor symlink, no host reads, no dropped package records | isolated mounted-image fixtures, path confinement, partial coverage receipt |
| G4 | Mutation tool validation | FC-17..19,23,29; source no-op parity, continuation-lines, NOT_RUN rejection, exact waivers | full mutant ledger, diff ledger, zero wrong kills, exact blockers |
| G5 | Release evidence regeneration | FC-21,22,24,38; intentionally stale/corrupt file tested separately from source code correctness | regenerated report, exact test inventory and SHA-bound manifest |
| G6 | Security governance and authenticity | FC-27,28,37,39; branch guard, verified signers, SBOM/attestation, private disclosure evidence | GitHub rule receipt; offline provenance verifier PASS; CVD status |
| G7 | Empirical validity | FC-31,32; independent corpus with labeled ground truth and base rate | field confusion matrix and confidence intervals, pre-registered claims |
| G8 | Representative environments | FC-33..36; privileged host, actual image, cross-platform builds, independent challenge | environment inventory, image digests, logs, external reviewer challenge set |

A successful G0–G6 does not automatically pass G7–G8. An experimental release can be described with boundaries, but *assurance-grade* claim stays on HOLD until all applicable gates are satisfied.

## 5. Protocol execution (non-destructive on checkout)

Use a clean checkout of the exact pinned commit in a fresh Linux environment; audit source only, never execute untrusted sample programs or compromised images on a production workstation. Before tests, record host kernel, Python, git HEAD and tool versions. Never use `sudo` for ordinary tests.

```bash
set -euo pipefail
git rev-parse HEAD
# Expected: 41745142378ccab363974db9f3cd568188706524
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[dev]'
sha256sum -c SOURCE_MANIFEST.sha256
python tools/build_release.py --check-manifest
python -m unittest discover -s tests -q
python tools/gate.py
python tools/mutate.py --coverage
python tools/mutate.py --module shell_syntax --module report --module safety
python tools/mutate.py --all --workers 2 --json mutation-full.json --markdown mutation-full.md
python tools/validity.py --check
python tools/release_evidence.py --check
```

**Do not trust the last two commands as final acceptance until FC-21/24/38 are repaired.** The commands above reproduce the *existing* gate, not the demanded future corrected contract. To close each finding, add a regression in `tests/test_*`, execute its negative control against a deliberately faulty isolated copy, prove the test fails there, then prove it passes on the patched implementation. For mutation waivers, retain only individually justified equivalence; never waive the whole line.

Archive a receipt per gate with `commit_sha`, `test_inputs_sha256`, `toolchain`, `environment`, `command`, `exit`, `test_count`, `failure_count`, `skipped_count`, `not_run_count`, `incomplete_reason_codes`, `artifact_sha256`, `evidence_links` and `claim_scope`. Each recorded result needs exact file hash binding; never hand-edit a green result.

## 6. Priority and release policy

- **Blocker A (immediate):** FC-05/07/08 (silent wrong trust/completeness), FC-12/14/15/16 (absence-based false proofs and host mixing), FC-23/24/25/28/38 (invalid evidence/CI provenance).
- **Blocker B (before claiming strong assurance):** other active SC+RR issues FC-01..23, FC-30, branch/tag identity and release provenance FC-26/27/37.
- **External-validation boundary:** FC-31..36 and FC-39 cannot be silently marked PASS; record independent verification or explicitly scope out the claim.

No CVSS score is asserted because exploitation preconditions, exposure and impact were not quantified. Review P1/P2 labels are triage priorities, not a standard vulnerability score.

## 7. Standards and theoretical sources

- NIST SP 800-61 Rev.3 (2025), *Incident Response Recommendations and Considerations for Cybersecurity Risk Management*: https://csrc.nist.gov/pubs/sp/800/61/r3/final
- NIST SP 800-86 (2006), *Guide to Integrating Forensic Techniques into Incident Response*: https://csrc.nist.gov/pubs/sp/800/86/final
- NIST SP 800-218 SSDF v1.1 final (2022; v1.2 was a draft in late 2025): https://csrc.nist.gov/pubs/sp/800/218/final
- OpenSSF OSPS Baseline v2026.08.28: https://baseline.openssf.org/versions/2026-08-28 (Level 1 applicable to any project, Level 2 assumes ≥2 maintainers; do not demand a second human approver for a solo developer as if it were universally mandatory.)
- SLSA specification v1.2: https://slsa.dev/spec/v1.2/
- Stefan Axelsson (2000), *The Base-Rate Fallacy and the Difficulty of Intrusion Detection*: https://profsandhu.com/cs6393_s21/Axelsson-2000.pdf
- Sommer & Paxson (2010), *Outside the Closed World*: https://doi.org/10.1109/SP.2010.25

These frameworks are used as *requirements and analytical methods*, not as a claim that NIST, OpenSSF, MITRE or SLSA has certified the repository.

## 8. Final finding

**Release-assurance status: HOLD.** Confirmed strong implementation elements: repeatable CI at exact head, CI matrix, bounded execution and reporting design, separate threat model, 906 tests and ~93% coverage in latest CI. However, current source still allows silence instead of uncertainty in selected execution paths; observations can be mismatched or partial; mutation and release evidence can produce misleading green outcomes; field detection efficacy is unverified. A high-assurance release claim cannot be certified from these artifacts. This verdict is bounded to source and CI audit, not a claim that the project cannot be usefully run as a clearly labeled experimental offline triage utility.
