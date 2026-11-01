# Bibliography

Every entry below was verified on 2026-10-31 against a primary page — the
publisher's DOI target, the standards body's own publication page, the
conference's own proceedings page or the authors' official host — showing
title, authors and venue. Tier 1: peer-reviewed venues and standards bodies.
Tier 2: industry frameworks with named maintainers. Tier 3: canonical books,
technical reports and tool documentation. Each entry states what in falsicore
it grounds; a source grounds a design decision, it does not certify the tool.
Two candidates without a surviving primary host are listed at the end as
*not cited*.

## 1. Why the verdict is bounded: evaluating detectors honestly

- **[Axelsson 2000]** Axelsson, S. *The base-rate fallacy and the difficulty of intrusion detection.* ACM TISSEC 3(3), 186–205, 2000. doi:10.1145/357830.357849. (T1)
  Grounds: compromise is rare on a given workstation, so even a detector with a low false-positive rate produces mostly false alarms; hence every finding is an *indicator* with stated benign alternatives, never a verdict (`guide.py`, `INDICATOR`/`EXPOSURE` kinds).
- **[McHugh 2000]** McHugh, J. *Testing Intrusion Detection Systems: A Critique of the 1998 and 1999 DARPA Intrusion Detection System Evaluations.* ACM TISSEC 3(4), 262–294, 2000. doi:10.1145/382912.382923. (T1)
  Grounds: a synthetic corpus measures what was planted, not the world; `docs/DETECTION_VALIDITY.json` says "recall on synthetic shapes" and never "sensitivity".
- **[Sommer & Paxson 2010]** Sommer, R.; Paxson, V. *Outside the Closed World: On Using Machine Learning for Network Intrusion Detection.* IEEE S&P 2010, 305–316. doi:10.1109/SP.2010.25. (T1)
  Grounds: the cost of false positives and the semantic gap between a signal and an incident; the tool emits deterministic rules with explanations instead of a learned score.
- **[Rossow et al. 2012]** Rossow, C.; Dietrich, C. J.; Grier, C.; Kreibich, C.; Paxson, V.; Pohlmann, N.; Bos, H.; van Steen, M. *Prudent Practices for Designing Malware Experiments: Status Quo and Outlook.* IEEE S&P 2012, 65–79. doi:10.1109/SP.2012.14. (T1)
  Grounds: the validity harness states its corpus, its environment and its limits, keeps negative results, and treats "not measured" as not measured (`docs/AUDIT.md`, `tools/validity.py`).
- **[Pendlebury et al. 2019]** Pendlebury, F.; Pierazzi, F.; Jordaney, R.; Kinder, J.; Cavallaro, L. *TESSERACT: Eliminating Experimental Bias in Malware Classification across Space and Time.* USENIX Security 2019. usenix.org/conference/usenixsecurity19/presentation/pendlebury. (T1)
  Grounds: a fixed fixture set decays; the validity table is regenerated and checked on every commit rather than quoted once.
- **[Arp et al. 2022]** Arp, D.; Quiring, E.; Pendlebury, F.; Warnecke, A.; Pierazzi, F.; Wressnegger, C.; Cavallaro, L.; Rieck, K. *Dos and Don'ts of Machine Learning in Computer Security.* USENIX Security 2022. usenix.org/conference/usenixsecurity22/presentation/arp. (T1)
  Grounds: the measurement contract in `docs/ASSURANCE.md` (test count ≠ efficacy, coverage ≠ correctness, synthetic precision ≠ field precision).
- **[Denning 1987]** Denning, D. E. *An Intrusion-Detection Model.* IEEE TSE SE-13(2), 222–232, 1987. doi:10.1109/TSE.1987.232894. (T1)
  Grounds: the observation → rule → report separation and the audit-record origin of host-based detection.
- **[Anderson 1980]** Anderson, J. P. *Computer Security Threat Monitoring and Surveillance.* Technical report, James P. Anderson Co., 1980. NIST CSRC early-papers archive (ande80.pdf). (T3)
  Grounds: authentication logs as a primary source (`auth` collector) and the limits of audit trails under a privileged adversary.
- **[Forrest et al. 1996]** Forrest, S.; Hofmeyr, S. A.; Somayaji, A.; Longstaff, T. A. *A Sense of Self for Unix Processes.* IEEE S&P 1996, 120–128. doi:10.1109/SECPRI.1996.502675. (T1)
  Grounds: why falsicore does *not* profile behaviour: a snapshot tool has no baseline of normal, so it compares against records (package databases, kernel views) instead.
- **[Strom et al. 2020]** Strom, B. E.; Applebaum, A.; Miller, D. P.; Nickels, K. C.; Pennington, A. G.; Thomas, C. B. *MITRE ATT&CK: Design and Philosophy.* MITRE MP180360R1, rev. March 2020. (T2)
  Grounds: the `attack_technique` field on findings is a hypothesis label (T1053.003, T1014, …), never attribution.

## 2. What a live scan can and cannot trust

- **[Thompson 1984]** Thompson, K. *Reflections on Trusting Trust.* CACM 27(8), 761–763, 1984. doi:10.1145/358198.358210. (T1)
  Grounds: the stated trust boundary — a root, kernel or firmware adversary forges every observation, package records included (`README` Limitations, `cannot_exclude`).
- **[Wheeler 2005]** Wheeler, D. A. *Countering Trusting Trust through Diverse Double-Compiling.* ACSAC 2005, 33–48. doi:10.1109/CSAC.2005.17. (T1)
  Grounds: two independent routes to the same fact is the only defence against a forged view; the pattern behind cross-view consistency and double builds.
- **[Saltzer & Schroeder 1975]** Saltzer, J. H.; Schroeder, M. D. *The Protection of Information in Computer Systems.* Proc. IEEE 63(9), 1278–1308, 1975. doi:10.1109/PROC.1975.9939. (T1)
  Grounds: fail-safe defaults and least privilege — the executor's allowlist, no shell, private 0700 reports, `PARTIAL` whenever a target was not fully inspected.
- **[Wang et al. 2005]** Wang, Y.-M.; Beck, D.; Vo, B.; Roussev, R.; Verbowski, C. *Detecting Stealth Software with Strider GhostBuster.* DSN 2005, 368–377. doi:10.1109/DSN.2005.39. (T1)
  Grounds: cross-view diff — the `crossview` collector compares the PID sweep with the `/proc` listing, sysfs with `/proc/modules`, `/proc/net` with netlink, and reports the difference without a signature.
- **[Jones et al. 2008]** Jones, S. T.; Arpaci-Dusseau, A. C.; Arpaci-Dusseau, R. H. *VMM-based Hidden Process Detection and Identification Using Lycosid.* VEE 2008, 91–100. doi:10.1145/1346256.1346269. (T1)
  Grounds: hidden-process detection by view comparison is reliable only with race handling; the confirming pass and `Tgid` check in `_hidden_processes`.
- **[Garfinkel & Rosenblum 2003]** Garfinkel, T.; Rosenblum, M. *A Virtual Machine Introspection Based Architecture for Intrusion Detection.* NDSS 2003. ndss-symposium.org. (T1)
  Grounds: observation from outside the subject's kernel is the stronger method; falsicore's offline image mode (`--root`) is the disk-only counterpart and names what it cannot see.
- **[Petroni et al. 2004]** Petroni, N. L.; Fraser, T.; Molina, J.; Arbaugh, W. A. *Copilot — a Coprocessor-based Kernel Runtime Integrity Monitor.* USENIX Security 2004. (T1)
  Grounds: kernel integrity needs an independent vantage point; a user-space tool reports `kernel` state as context only.
- **[Kruegel et al. 2004]** Kruegel, C.; Robertson, W.; Vigna, G. *Detecting Kernel-Level Rootkits Through Binary Analysis.* ACSAC 2004, 91–100. doi:10.1109/CSAC.2004.19. (T1)
  Grounds: the `HIDDEN_KERNEL_MODULE` rule is a presence check, not an analysis of module code; module names are hashed because they are attacker-controlled.
- **[Kim & Spafford 1994]** Kim, G. H.; Spafford, E. H. *The Design and Implementation of Tripwire: A File System Integrity Checker.* ACM CCS 1994, 18–29. doi:10.1145/191177.191183. (T1)
  Grounds: integrity by recorded digest, and its limit: the record and the file live on the same disk (`falsicore/packages.py`, "what a digest proves").

## 3. Forensic process and offline analysis

- **[NIST SP 800-86]** Kent, K.; Chevalier, S.; Grance, T.; Dang, H. *Guide to Integrating Forensic Techniques into Incident Response.* NIST SP 800-86, 2006. doi:10.6028/NIST.SP.800-86. (T1)
  Grounds: analysis of acquired media rather than the running subject (`scan --root`), evidence provenance (hash manifests, `private_index.json` kept separate).
- **[NIST SP 800-61r3]** Nelson, A.; Rekhi, S.; Souppaya, M.; Scarfone, K. *Incident Response Recommendations and Considerations for Cybersecurity Risk Management.* NIST SP 800-61 Rev. 3, April 2025. doi:10.6028/NIST.SP.800-61r3. (T1)
  Grounds: the three-way outcome (suspicious / inconclusive / no indicators observed) and non-destructive next steps.
- **[Carrier & Spafford 2003]** Carrier, B.; Spafford, E. H. *Getting Physical with the Digital Investigation Process.* IJDE 2(2); CERIAS TR 2003-29, Purdue. (T3; verified via the authors' institutional report page)
  Grounds: preservation before analysis — the tool never remediates and tells the operator to save evidence first.

## 4. Building and testing the tool itself

- **[NIST SP 800-218]** Souppaya, M.; Scarfone, K.; Dodson, D. *Secure Software Development Framework (SSDF) Version 1.1.* NIST SP 800-218, February 2022. doi:10.6028/NIST.SP.800-218. (T1) — v1.2 (Rev. 1) was an Initial Public Draft on the verification date and is not cited.
  Grounds: PW.7/PW.8 (review and test before release, keep results), PS.2/PS.3 (release integrity), RV.1/RV.2 (defect register with regression tests).
- **[Lamb & Zacchiroli 2022]** Lamb, C.; Zacchiroli, S. *Reproducible Builds: Increasing the Integrity of Software Supply Chains.* IEEE Software 39(2), 62–70, 2022. doi:10.1109/MS.2021.3073045. (T1)
  Grounds: two builds of one snapshot must be byte-identical (claim C7), with the archive hash kept outside the archive.
- **[SLSA v1.2]** OpenSSF. *Supply-chain Levels for Software Artifacts, specification v1.2 (Approved).* slsa.dev/spec/v1.2/. (T2)
  Grounds: what the checksum does *not* give — provenance and authorship; stated in `SECURITY.md` and `docs/VERIFICATION.md`.
- **[OSPS Baseline 2026.08.28]** OpenSSF Security Baseline SIG. *Open Source Project Security Baseline.* baseline.openssf.org. (T2)
  Grounds: CI, disclosure policy and pinned automation.
- **[DeMillo, Lipton & Sayward 1978]** DeMillo, R. A.; Lipton, R. J.; Sayward, F. G. *Hints on Test Data Selection: Help for the Practicing Programmer.* IEEE Computer 11(4), 34–41, 1978. doi:10.1109/C-M.1978.218136. (T1)
  Grounds: mutation testing as the question "would a test notice a small fault?" (`tools/mutate.py`, `docs/MUTATION.md`).
- **[Jia & Harman 2011]** Jia, Y.; Harman, M. *An Analysis and Survey of the Development of Mutation Testing.* IEEE TSE 37(5), 649–678, 2011. doi:10.1109/TSE.2010.62. (T1)
  Grounds: the equivalent-mutant problem — survivors are candidates; equivalence is shown and annotated with a reason, never assumed.
- **[Papadakis et al. 2019]** Papadakis, M.; Kintis, M.; Zhang, J.; Jia, Y.; Le Traon, Y.; Harman, M. *Mutation Testing Advances: An Analysis and Survey.* Advances in Computers 112, 275–378, 2019. doi:10.1016/bs.adcom.2018.03.015. (T3)
  Grounds: test selection per mutant and the cost model behind the diff gate.
- **[Just et al. 2014]** Just, R.; Jalali, D.; Inozemtseva, L.; Ernst, M. D.; Holmes, R.; Fraser, G. *Are Mutants a Valid Substitute for Real Faults in Software Testing?* FSE 2014, 654–665. doi:10.1145/2635868.2635929. (T1)
  Grounds: mutation score correlates with real-fault detection, with exceptions; it is reported as a property of the suite, not of the tool's detection power.
- **[Inozemtseva & Holmes 2014]** Inozemtseva, L.; Holmes, R. *Coverage Is Not Strongly Correlated with Test Suite Effectiveness.* ICSE 2014, 435–445. doi:10.1145/2568225.2568271. (T1)
  Grounds: why the 91 % branch coverage figure is reported with a denominator and never as assurance.
- **[Claessen & Hughes 2000]** Claessen, K.; Hughes, J. *QuickCheck: A Lightweight Tool for Random Testing of Haskell Programs.* ICFP 2000, 268–279. doi:10.1145/351240.351266. (T1)
  Grounds: properties as universally quantified, refutable claims (`tests/test_properties.py`).
- **[MacIver et al. 2019]** MacIver, D. R.; Hatfield-Dodds, Z.; et al. *Hypothesis: A new approach to property-based testing.* JOSS 4(43), 1891, 2019. doi:10.21105/joss.01891. (T1)
  Grounds: the property-testing library used in CI (development dependency only; the shipped tool stays standard-library).

## 5. Tools of the same family (Tier 3, for comparison)

- **[unhide]** YJesus et al. *Unhide: forensic tool to find hidden processes and TCP/UDP ports.* unhide-forensics.info; github.com/YJesus/Unhide (GPL-3.0). Version and date not published.
- **[chkrootkit]** Murilo, N.; Steding-Jessen, K. *chkrootkit 0.59 (2026-01-01).* chkrootkit.org.
- **[rkhunter]** Boelen, M.; project team. *Rootkit Hunter 1.4.6 (2018-02-20).* rkhunter.sourceforge.net.
  Grounds: the brute-force PID sweep and the `/proc`-versus-netlink comparison follow the techniques these tools made standard; falsicore adds the confirming pass, the closed coverage vocabulary and the refutable validity table.

## 6. Method anchor

- **[Popper 2002]** Popper, K. *The Logic of Scientific Discovery.* Routledge Classics, 2002. ISBN 978-0-415-27844-7. (T3)
  Grounds: the tool never asserts "clean"; every claim in the README names what would refute it.

## Not cited (no surviving primary host on the verification date)

- Casey, E. *Error, Uncertainty and Loss in Digital Evidence.* IJDE 1(2), 2002 — the publisher's site no longer resolves; only third-party reference lists remain.
- Rutkowska, J. *Introducing Stealth Malware Taxonomy.* COSEINC white paper, 2006 — original host gone; only mirrors.
