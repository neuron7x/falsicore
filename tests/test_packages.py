"""falsicore.packages: manager detection and pure, total package-database parsers.

Fixtures are written from the published formats (mtree(5)/libarchive, apk-tools
2.x `installed`, rpm's verify.c, apt/dnf/pacman configuration manuals), not
captured from a live host. Where a format detail is uncertain the fixture says
so and the parser's behaviour is the conservative one.
"""
from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from falsicore import packages as p

try:
    from hypothesis import HealthCheck, given, settings
    from hypothesis import strategies as st
    HAVE_HYPOTHESIS = True
except ImportError:  # pragma: no cover - exercised only where Hypothesis is absent
    HAVE_HYPOTHESIS = False

if HAVE_HYPOTHESIS:
    settings.register_profile(
        "falsicore",
        deadline=None, database=None,
        max_examples=int(os.environ.get("FALSICORE_PBT_EXAMPLES", "200")),
        suppress_health_check=[HealthCheck.too_slow, HealthCheck.filter_too_much],
    )
    settings.load_profile("falsicore")
    # One physical line as str.splitlines() sees it (same model as test_properties).
    ONE_LINE = st.characters(blacklist_categories=("Cs", "Zl", "Zp"),
                             blacklist_characters="\x00\n\r\x0b\x0c\x1c\x1d\x1e\x85")
    any_text = st.text(max_size=400)
    any_bytes = st.binary(max_size=600)
    manager = st.sampled_from(["apt", "dnf", "pacman", "apk", "zypper", ""])
    path_part = st.from_regex(r"\A[a-z][a-z0-9._-]{0,8}\Z")
    rpm_column = st.text(st.sampled_from("SM5DLUGTP.?"), min_size=8, max_size=9)
    rpm_type = st.sampled_from(["", "c", "d", "g", "l", "r"])
else:  # pragma: no cover
    def given(*_a, **_k):  # type: ignore[misc]
        return lambda f: f


MD5 = "0123456789abcdef0123456789abcdef"
SHA256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

# A pacman local-db mtree as libarchive writes it (gunzipped): header, /set
# defaults, metadata entries that never land on disk, dirs, files, a link.
MTREE_SAMPLE = f"""#mtree
/set type=file uid=0 gid=0 mode=644
./.BUILDINFO time=1702000000.0 size=5143 md5digest={MD5} sha256digest={SHA256}
./.PKGINFO time=1702000000.0 size=446 md5digest={MD5} sha256digest={SHA256}
/set mode=755
./usr time=1702000000.0 type=dir
./usr/bin time=1702000000.0 type=dir
./usr/bin/which time=1702000000.0 size=26192 md5digest={MD5} sha256digest={SHA256}
./usr/share time=1702000000.0 type=dir
./usr/share/man time=1702000000.0 type=dir
./usr/share/man/man1 time=1702000000.0 type=dir
/set mode=644
./usr/share/man/man1/which.1.gz time=1702000000.0 size=1189 md5digest={MD5} sha256digest={SHA256}
./usr/lib/libfoo.so.1 time=1702000000.0 mode=777 type=link link=libfoo.so.1.0
./usr/share/doc/foo/read\\040me.txt time=1702000000.0 size=3 md5digest={MD5} sha256digest={SHA256}
./usr/share/foo/a\\sb time=1702000000.0 size=3 md5digest={MD5} sha256digest={SHA256}
./usr/share/foo/caf\\303\\251 time=1702000000.0 size=3 md5digest={MD5} sha256digest={SHA256}
""".encode()

# apk-tools 2.x /lib/apk/db/installed: blank-line separated records. The order
# R: then a: then Z: follows apk_db_write_fdb(); a: is written only for files
# whose owner/mode differ from the root:root 0644 default [not verified on a
# live host; the parser accepts a: and Z: in either order after an R:].
APK_SAMPLE = """C:Q1Sl6qa5WwBc5eMv4h3Nj9jT4XqHM=
P:busybox
V:1.36.1-r29
A:x86_64
S:654321
I:962560
T:Size optimized toolbox of many common UNIX utilities
U:https://busybox.net/
L:GPL-2.0-only
o:busybox
m:Maintainer Name <maintainer@example.invalid>
t:1715000000
c:abcdef0123456789abcdef0123456789abcdef01
D:so:libc.musl-x86_64.so.1
p:/bin/sh cmd:busybox=1.36.1-r29 cmd:sh=1.36.1-r29
r:busybox-initscripts
F:bin
R:busybox
a:0:0:755
Z:Q1aENjQU6YfKbMrdZ0PY2E5dCV3NA=
R:sh
a:0:0:777
Z:Q1pcfTfDNEbNKQc2s1tia7da05M8Q=
F:etc
R:securetty
Z:Q1mB95Hq2NUTZ599RDiSsj9w5FrOU=
F:etc/busybox-paths.d
M:0:0:755
R:busybox
Z:Q1mB95Hq2NUTZ599RDiSsj9w5FrOU=
F:usr
F:usr/sbin
R:crond
a:0:0:755
Z:Q1aENjQU6YfKbMrdZ0PY2E5dCV3NA=

C:Q1Tl6qa5WwBc5eMv4h3Nj9jT4XqHM=
P:musl
V:1.2.5-r0
A:x86_64
F:lib
R:ld-musl-x86_64.so.1
a:0:0:755
Z:Q1aENjQU6YfKbMrdZ0PY2E5dCV3NA=
R:libc.musl-x86_64.so.1
a:0:0:777
Z:Q1aENjQU6YfKbMrdZ0PY2E5dCV3NA=
""".encode()

# rpm -Va as formatted by rpm's verify.c: "%s  %c %s" (9 attribute columns,
# type marker or space, path) and "missing   %c %s", with " (strerror)" appended
# when lstat failed for a reason other than ENOENT.
RPM_SAMPLE = """S.5....T.  c /etc/ssh/sshd_config
.M.......    /usr/bin/ping
.......T.    /usr/lib64/libfoo.so.1
.....UG..    /var/lib/x
missing     /usr/share/doc/bar/README
missing   d /usr/share/doc/bar/CHANGES
missing     /usr/lib/.build-id/ab/cdef
..?......    /usr/bin/sudo
S.?....T.    /usr/bin/passwd
missing     /root/.secret (Permission denied)
Unsatisfied dependencies for baz-1.0-1.fc40.x86_64:
\tlibqux.so.2()(64bit) is needed by baz-1.0-1.fc40.x86_64
S.5....T.    /usr/lib/python3.12/site-packages/x.pyc
..5....T.  c /etc/sudoers
error: cannot open Packages database in /var/lib/rpm
"""


class DetectManagersTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def touch(self, relative: str) -> Path:
        target = self.root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(b"")
        return target

    def test_empty_root_detects_nothing(self):
        self.assertEqual(p.detect_managers(self.root), [])

    def test_missing_root_detects_nothing(self):
        self.assertEqual(p.detect_managers(self.root / "absent"), [])

    def test_all_four_sorted(self):
        self.touch("var/lib/dpkg/status")
        self.touch("var/lib/rpm/rpmdb.sqlite")
        (self.root / "var/lib/pacman/local").mkdir(parents=True)
        self.touch("lib/apk/db/installed")
        self.assertEqual(p.detect_managers(self.root), ["apk", "dpkg", "pacman", "rpm"])

    def test_rpm_alternate_location_and_bdb_name(self):
        self.touch("usr/lib/sysimage/rpm/Packages")
        self.assertEqual(p.detect_managers(self.root), ["rpm"])

    def test_rpm_empty_directory_is_not_a_database(self):
        # Debian's optional rpm tool ships /var/lib/rpm without a database.
        (self.root / "var/lib/rpm").mkdir(parents=True)
        self.assertEqual(p.detect_managers(self.root), [])

    def test_status_must_be_a_regular_file(self):
        (self.root / "var/lib/dpkg/status").mkdir(parents=True)
        self.assertEqual(p.detect_managers(self.root), [])

    def test_pacman_local_must_be_a_directory(self):
        self.touch("var/lib/pacman/local")
        self.assertEqual(p.detect_managers(self.root), [])

    def test_symlinked_component_is_not_followed(self):
        real = self.root / "elsewhere"
        (real / "dpkg").mkdir(parents=True)
        (real / "dpkg" / "status").write_bytes(b"")
        (self.root / "var/lib").mkdir(parents=True)
        (self.root / "var/lib/dpkg").symlink_to(real / "dpkg")
        self.assertEqual(p.detect_managers(self.root), [])

    def test_symlinked_final_component_is_not_followed(self):
        self.touch("real_status")
        (self.root / "var/lib/dpkg").mkdir(parents=True)
        (self.root / "var/lib/dpkg/status").symlink_to(self.root / "real_status")
        self.assertEqual(p.detect_managers(self.root), [])

    def test_fedora_rpm_symlink_found_through_real_directory(self):
        self.touch("usr/lib/sysimage/rpm/rpmdb.sqlite")
        (self.root / "var/lib").mkdir(parents=True)
        (self.root / "var/lib/rpm").symlink_to(Path("../../usr/lib/sysimage/rpm"))
        self.assertEqual(p.detect_managers(self.root), ["rpm"])

    def test_symlinked_rpmdb_file_is_not_followed(self):
        self.touch("Packages.real")
        (self.root / "var/lib/rpm").mkdir(parents=True)
        (self.root / "var/lib/rpm/Packages").symlink_to(self.root / "Packages.real")
        self.assertEqual(p.detect_managers(self.root), [])

    def test_default_root_is_slash_and_total(self):
        # The host's own answer is environment-dependent; only shape is asserted.
        result = p.detect_managers()
        self.assertEqual(result, sorted(set(result)))
        self.assertTrue(set(result) <= set(p.MANAGERS))


class PacmanMtreeTests(unittest.TestCase):
    def test_sample_entries_and_inheritance(self):
        entries, stats = p.parse_pacman_mtree(MTREE_SAMPLE)
        self.assertEqual(stats, {"lines": 17, "malformed": 0, "truncated": False})
        which = entries["/usr/bin/which"]
        self.assertEqual(which, {"type": "file", "uid": 0, "gid": 0, "mode": 0o755, "size": 26192,
                                 "md5": MD5, "sha256": SHA256})
        # /set mode=644 after the man1 directory resets the inherited mode.
        self.assertEqual(entries["/usr/share/man/man1/which.1.gz"]["mode"], 0o644)
        self.assertEqual(entries["/usr/bin"], {"type": "dir", "uid": 0, "gid": 0, "mode": 0o755})
        self.assertEqual(entries["/usr/lib/libfoo.so.1"],
                         {"type": "link", "uid": 0, "gid": 0, "mode": 0o777, "link": "libfoo.so.1.0"})
        self.assertIn("/.PKGINFO", entries)
        self.assertTrue({"/.BUILDINFO", "/.PKGINFO"} <= p.PACMAN_METADATA_ENTRIES)

    def test_vis_escapes_in_paths(self):
        entries, stats = p.parse_pacman_mtree(MTREE_SAMPLE)
        self.assertEqual(stats["malformed"], 0)
        self.assertIn("/usr/share/doc/foo/read me.txt", entries)
        self.assertIn("/usr/share/foo/a b", entries)
        self.assertIn("/usr/share/foo/café", entries)

    def test_vis_escapes_in_link_target_and_other_c_escapes(self):
        raw = b"./a type=link link=x\\sy\\011z\\\\w\\#q\n"
        entries, stats = p.parse_pacman_mtree(raw)
        self.assertEqual(stats["malformed"], 0)
        self.assertEqual(entries["/a"]["link"], "x y\tz\\w#q")

    def test_unknown_or_dangling_escape_is_malformed(self):
        for raw in (b"./a\\q type=file\n", b"./a\\ type=file\n", b"./a\\400 type=file\n", b"./a\\^A type=file\n"):
            entries, stats = p.parse_pacman_mtree(raw)
            self.assertEqual((entries, stats["malformed"]), ({}, 1), raw)

    def test_octal_escape_of_one_and_two_digits(self):
        entries, stats = p.parse_pacman_mtree(b"./a\\7b type=file\n./c\\40d type=file\n")
        self.assertEqual(stats["malformed"], 0)
        self.assertEqual(set(entries), {"/a\x07b", "/c d"})

    def test_empty_and_comment_only(self):
        self.assertEqual(p.parse_pacman_mtree(b""), ({}, {"lines": 0, "malformed": 0, "truncated": False}))
        self.assertEqual(p.parse_pacman_mtree(b"#mtree\n\n# x\n"),
                         ({}, {"lines": 3, "malformed": 0, "truncated": False}))

    def test_root_entry_and_absolute_form(self):
        # "." is the root; a token starting with "/" is an mtree special command, not a path.
        entries, stats = p.parse_pacman_mtree(b". type=dir\n/usr/bin/x type=file size=1\n")
        self.assertEqual(stats["malformed"], 1)
        self.assertEqual(entries, {"/": {"type": "dir"}})

    def test_malformed_lines_counted_and_dropped_whole(self):
        raw = (b"bogus line\n"                    # relative classic form: unsupported
               b"./x mode=999\n"                  # non-octal mode
               b"./y mode=17777\n"                # > 07777
               b"./z type=weird\n"                # unknown type
               b"./w md5digest=abc\n"             # wrong digest length
               b"./v sha256digest=" + b"g" * 64 + b"\n"  # non-hex
               b"./u uid=-1\n"
               b"./t =value\n"                    # token without keyword
               b"./s type\n"                      # retained keyword without value
               b"./r/../q type=file\n"            # parent component
               b"./p//o type=file\n"              # empty component
               b"/unknowncommand type=file\n"
               b"/set mode=zzz\n"
               b"/unset\n"
               b"/unset mode=1\n"
               b"./ok type=file size=5\n")
        entries, stats = p.parse_pacman_mtree(raw)
        self.assertEqual(stats, {"lines": 16, "malformed": 15, "truncated": False})
        self.assertEqual(entries, {"/ok": {"type": "file", "size": 5}})

    def test_unknown_and_ignored_keywords_are_not_malformed(self):
        raw = b"./a type=file time=1.5 uname=root gname=root optional nochange sha1digest=ab futurekey=1 flag\n"
        entries, stats = p.parse_pacman_mtree(raw)
        self.assertEqual(stats["malformed"], 0)
        self.assertEqual(entries["/a"], {"type": "file"})

    def test_unset_removes_defaults(self):
        raw = (b"/set type=file mode=644 uid=0\n./a size=1\n/unset mode\n./b size=1\n"
               b"/unset all\n./c size=1\n/set md5digest=" + MD5.encode() + b"\n./d size=1\n/unset md5\n./e size=1\n")
        entries, stats = p.parse_pacman_mtree(raw)
        self.assertEqual(stats["malformed"], 0)
        self.assertEqual(entries["/a"], {"type": "file", "mode": 0o644, "uid": 0, "size": 1})
        self.assertEqual(entries["/b"], {"type": "file", "uid": 0, "size": 1})
        self.assertEqual(entries["/c"], {"size": 1})
        self.assertEqual(entries["/d"], {"md5": MD5, "size": 1})
        self.assertEqual(entries["/e"], {"size": 1})

    def test_entry_keyword_overrides_default_and_digests_lowercased(self):
        raw = b"/set mode=644 type=file\n./a mode=4755 md5digest=" + MD5.upper().encode() + b"\n"
        entries, _ = p.parse_pacman_mtree(raw)
        self.assertEqual(entries["/a"], {"type": "file", "mode": 0o4755, "md5": MD5})

    def test_duplicate_path_last_wins(self):
        entries, _ = p.parse_pacman_mtree(b"./a size=1\n./a size=2\n")
        self.assertEqual(entries["/a"], {"size": 2})

    def test_crlf_and_blank_lines(self):
        entries, stats = p.parse_pacman_mtree(b"./a size=1\r\n\r\n./b size=2\r\n")
        self.assertEqual(stats, {"lines": 3, "malformed": 0, "truncated": False})
        self.assertEqual(set(entries), {"/a", "/b"})

    def test_non_utf8_bytes_are_replaced_not_raised(self):
        entries, stats = p.parse_pacman_mtree(b"./\xff\xfe type=file\n")
        self.assertEqual(stats["malformed"], 0)
        self.assertEqual(list(entries), ["/\ufffd\ufffd"])

    def test_truncation_at_line_bound(self):
        raw = b"".join(b"./f%d size=1\n" % i for i in range(p.MTREE_MAX_LINES + 5))
        entries, stats = p.parse_pacman_mtree(raw)
        self.assertEqual(stats, {"lines": p.MTREE_MAX_LINES, "malformed": 0, "truncated": True})
        self.assertEqual(len(entries), p.MTREE_MAX_LINES)

    def test_exactly_at_bound_is_not_truncated(self):
        raw = b"".join(b"./f%d size=1\n" % i for i in range(p.MTREE_MAX_LINES))
        _, stats = p.parse_pacman_mtree(raw)
        self.assertEqual(stats["truncated"], False)

    def test_too_many_keywords_on_a_line_is_malformed(self):
        raw = b"./a " + b" ".join(b"k%d=1" % i for i in range(65)) + b"\n"
        entries, stats = p.parse_pacman_mtree(raw)
        self.assertEqual((entries, stats["malformed"]), ({}, 1))


class ApkInstalledTests(unittest.TestCase):
    def test_sample_packages_and_files(self):
        db, stats = p.parse_apk_installed(APK_SAMPLE)
        self.assertEqual(stats, {"lines": APK_SAMPLE.count(b"\n"), "malformed": 0, "truncated": False})
        self.assertEqual(db["packages"], [{"name": "busybox", "version": "1.36.1-r29", "files": 5},
                                          {"name": "musl", "version": "1.2.5-r0", "files": 2}])
        self.assertEqual(db["files"]["/bin/busybox"],
                         {"package": "busybox", "uid": 0, "gid": 0, "mode": 0o755, "sha1_b64": "aENjQU6YfKbMrdZ0PY2E5dCV3NA="})
        # Default permissions: no a: line, so no mode.
        self.assertEqual(db["files"]["/etc/securetty"], {"package": "busybox", "sha1_b64": "mB95Hq2NUTZ599RDiSsj9w5FrOU="})
        # Multiple F: directories inside one record, including a nested one.
        self.assertIn("/etc/busybox-paths.d/busybox", db["files"])
        self.assertIn("/usr/sbin/crond", db["files"])
        self.assertEqual(db["files"]["/lib/libc.musl-x86_64.so.1"]["package"], "musl")
        self.assertEqual(db["files"]["/lib/libc.musl-x86_64.so.1"]["mode"], 0o777)

    def test_empty_input(self):
        self.assertEqual(p.parse_apk_installed(b""),
                         ({"packages": [], "files": {}}, {"lines": 0, "malformed": 0, "truncated": False}))

    def test_blank_lines_only(self):
        db, stats = p.parse_apk_installed(b"\n\n\n")
        self.assertEqual((db["packages"], stats), ([], {"lines": 3, "malformed": 0, "truncated": False}))

    def test_last_record_without_trailing_blank_line_is_committed(self):
        db, _ = p.parse_apk_installed(b"P:a\nV:1\nF:usr\nR:x\nZ:Q1aENjQU6YfKbMrdZ0PY2E5dCV3NA=")
        self.assertEqual(db["files"]["/usr/x"], {"package": "a", "sha1_b64": "aENjQU6YfKbMrdZ0PY2E5dCV3NA="})

    def test_record_without_name_is_dropped_and_counted_once(self):
        db, stats = p.parse_apk_installed(b"V:1\nF:usr\nR:x\nR:y\n\nP:ok\nV:2\n")
        self.assertEqual(db["packages"], [{"name": "ok", "version": "2", "files": 0}])
        self.assertEqual(db["files"], {})
        self.assertEqual(stats["malformed"], 1)

    def test_file_at_root_directory(self):
        db, stats = p.parse_apk_installed(b"P:a\nF:\nR:.dockerenv\n")
        self.assertEqual(stats["malformed"], 0)
        self.assertEqual(list(db["files"]), ["/.dockerenv"])

    def test_malformed_lines(self):
        raw = (b"P:a\n"
               b"R:early\n"               # R before any F
               b"a:0:0:755\n"             # a before any R
               b"Z:Q1aENjQU6YfKbMrdZ0PY2E5dCV3NA=\n"   # Z before any R
               b"F:usr/bin\n"
               b"R:with/slash\n"
               b"R:..\n"
               b"R:\n"
               b"R:ok\n"
               b"a:notperms\n"
               b"Z:Q9zzzz\n"              # unknown checksum prefix
               b"Z:Q1short=\n"
               b"nocolon\n"
               b"P\n"
               b"P:two words\n"
               b"F:../escape\n"
               b"R:after_bad_dir\n"
               b"F:/absolute\n"
               b"R:after_abs_dir\n")
        db, stats = p.parse_apk_installed(raw)
        self.assertEqual(stats["malformed"], 16)
        self.assertEqual(db["packages"], [{"name": "a", "version": "", "files": 1}])
        self.assertEqual(db["files"], {"/usr/bin/ok": {"package": "a"}})

    def test_q2_sha256_checksum_retained_separately(self):
        db, stats = p.parse_apk_installed(b"P:a\nF:usr\nR:x\nZ:Q2" + b"A" * 43 + b"=\n")
        self.assertEqual(stats["malformed"], 0)
        self.assertEqual(db["files"]["/usr/x"], {"package": "a", "sha256_b64": "A" * 43 + "="})

    def test_perms_with_xattr_checksum_suffix(self):
        db, stats = p.parse_apk_installed(b"P:a\nF:usr\nR:x\na:0:0:4755:Q1aENjQU6YfKbMrdZ0PY2E5dCV3NA=\n")
        self.assertEqual(stats["malformed"], 0)
        self.assertEqual(db["files"]["/usr/x"]["mode"], 0o4755)

    def test_unknown_keys_ignored(self):
        db, stats = p.parse_apk_installed(b"P:a\nV:1\nX:future\nq:other\nF:usr\nM:0:0:755\nR:x\n")
        self.assertEqual(stats["malformed"], 0)
        self.assertEqual(db["files"], {"/usr/x": {"package": "a"}})

    def test_non_utf8_is_replaced(self):
        db, stats = p.parse_apk_installed(b"P:a\nF:usr\nR:\xff\n")
        self.assertEqual(stats["malformed"], 0)
        self.assertEqual(list(db["files"]), ["/usr/\ufffd"])

    def test_truncation_drops_record_in_progress(self):
        head = b"P:first\nF:usr\n" + b"".join(b"R:f%d\n" % i for i in range(p.APK_MAX_LINES - 10)) + b"\n"
        tail = b"P:second\nF:usr\n" + b"".join(b"R:g%d\n" % i for i in range(40))
        db, stats = p.parse_apk_installed(head + tail)
        self.assertTrue(stats["truncated"])
        self.assertEqual(stats["lines"], p.APK_MAX_LINES)
        self.assertEqual([x["name"] for x in db["packages"]], ["first"])
        self.assertFalse(any(path.startswith("/usr/g") for path in db["files"]))


class RpmVerifyReviewTests(unittest.TestCase):
    def test_sample_classification(self):
        review = p.rpm_verify_review(RPM_SAMPLE)
        self.assertEqual(review["content_changed_conffiles"], 2)      # sshd_config, sudoers
        self.assertEqual(review["content_changed_other_files"], 1)    # x.pyc
        self.assertEqual(review["missing_files"], 3)
        self.assertEqual(review["unverifiable"], 3)                   # ..?, S.?, (Permission denied)
        self.assertEqual(review["metadata_changed_only"], 3)          # .M, ..T, UG
        self.assertEqual(review["dependency_problems"], 2)
        self.assertEqual(review["unparsed_lines"], 1)                 # error:
        self.assertEqual(review["missing_by_prefix"], {"/usr/share/doc": 2, "/usr/lib/.build-id": 1})
        nonblank = sum(1 for line in RPM_SAMPLE.splitlines() if line.split())
        self.assertEqual(sum(review[k] for k in p.RPM_REVIEW_COUNTERS), nonblank)

    def test_empty(self):
        review = p.rpm_verify_review("")
        self.assertEqual({k: review[k] for k in p.RPM_REVIEW_COUNTERS}, {k: 0 for k in p.RPM_REVIEW_COUNTERS})
        self.assertEqual(review["missing_by_prefix"], {})

    def test_eight_column_legacy_format(self):
        review = p.rpm_verify_review("S.5....T  c /etc/x\n.M......    /usr/bin/y\n")
        self.assertEqual((review["content_changed_conffiles"], review["metadata_changed_only"]), (1, 1))

    def test_digest_differs_wins_over_other_unverifiable_columns(self):
        self.assertEqual(p.rpm_verify_review("..5....?.    /usr/bin/x")["content_changed_other_files"], 1)

    def test_conffile_marker_only_for_c(self):
        review = p.rpm_verify_review("..5......  d /usr/share/doc/x\n..5......  g /var/log/x\n..5......  c /etc/x\n")
        self.assertEqual((review["content_changed_conffiles"], review["content_changed_other_files"]), (1, 2))

    def test_missing_with_conffile_marker_and_permission_denied(self):
        review = p.rpm_verify_review("missing   c /etc/x\nmissing   c /etc/y (Permission denied)\n")
        self.assertEqual((review["missing_files"], review["unverifiable"]), (1, 1))
        self.assertEqual(review["missing_by_prefix"], {"/etc/x": 1})

    def test_path_with_spaces(self):
        review = p.rpm_verify_review("missing     /usr/share/foo/read me.txt\n")
        self.assertEqual(review["missing_by_prefix"], {"/usr/share/foo": 1})

    def test_all_dot_column_is_unparsed_not_a_change(self):
        review = p.rpm_verify_review(".........    /usr/bin/x\n")
        self.assertEqual((review["unparsed_lines"], review["metadata_changed_only"]), (1, 0))

    def test_column_without_path_is_unparsed(self):
        review = p.rpm_verify_review(".M.......\n.M.......    relative/path\nmissing\n")
        self.assertEqual(review["unparsed_lines"], 3)

    def test_dependency_lines(self):
        text = ("Unsatisfied dependencies for a-1-1.x86_64:\n\tb is needed by a-1-1.x86_64\n"
                "\tc conflicts with a-1-1.x86_64\n\td is obsoleted by a-1-1.x86_64\n")
        self.assertEqual(p.rpm_verify_review(text)["dependency_problems"], 4)

    def test_prefix_table_is_top_ten(self):
        text = "\n".join(f"missing     /d{i}/x/y/z" for i in range(30))
        review = p.rpm_verify_review(text)
        self.assertEqual(review["missing_files"], 30)
        self.assertEqual(len(review["missing_by_prefix"]), 10)


class RepoSettingsTests(unittest.TestCase):
    APT_ONE_LINE = ("deb http://deb.debian.org/debian bookworm main\n"
                    "# deb [trusted=yes] http://commented.invalid stable main\n"
                    "deb [arch=amd64 trusted=yes] http://local.invalid stable main\n"
                    "deb [allow-insecure=yes] http://weak.invalid stable main  # trailing\n")
    APT_DEB822 = ("Types: deb\nURIs: http://x.invalid\nSuites: stable\nComponents: main\n"
                  "Trusted: yes\nAllow-Weak: yes\nAllow-Downgrade-To-Insecure: true\n")
    APT_CONF = ('// Acquire::AllowInsecureRepositories "true";\n'
                '/* APT::Get::AllowUnauthenticated "true"; */\n'
                'Acquire::AllowInsecureRepositories "true";\n'
                '/* multi\nAPT::Get::AllowUnauthenticated "true";\nline */ Acquire::AllowWeakRepositories "true";\n')
    DNF_REPO = ("[fedora]\nname=Fedora\nmetalink=https://x.invalid\nenabled=1\n"
                "gpgcheck=0\n#repo_gpgcheck=0\n;sslverify=0\nsslverify = False\n")
    PACMAN = ("[options]\nSigLevel    = Required DatabaseOptional\nLocalFileSigLevel = Optional\n"
              "#SigLevel = Never\n[core]\nInclude = /etc/pacman.d/mirrorlist\n"
              "[custom]\nSigLevel = Optional TrustAll\nServer = file:///srv/pkgs\n")

    def test_apt_one_line(self):
        self.assertEqual(p.detect_insecure_repo_settings("apt", self.APT_ONE_LINE), ["APT_ALLOW_INSECURE", "APT_TRUSTED_YES"])

    def test_apt_deb822(self):
        self.assertEqual(p.detect_insecure_repo_settings("apt", self.APT_DEB822),
                         ["APT_ALLOW_DOWNGRADE_TO_INSECURE", "APT_ALLOW_WEAK", "APT_TRUSTED_YES"])

    def test_apt_conf_comment_forms(self):
        self.assertEqual(p.detect_insecure_repo_settings("apt", self.APT_CONF), ["APT_ALLOW_INSECURE", "APT_ALLOW_WEAK"])

    def test_apt_negatives(self):
        text = ("deb [trusted=no] http://x stable main\nTrusted: no\nAllow-Insecure: no\n"
                "deb http://untrusted.invalid/trusted=yes stable main\n"      # inside the URI: data
                "deb http://x.invalid/ stable main [trusted=yes]\n"           # options must precede the URI
                "URIs: http://x.invalid/?trusted=yes\n"
                "X-Trusted: yes\n"
                'Acquire::AllowInsecureRepositories "false";\n'
                "deb [arch=amd64] http://x stable main\n")
        self.assertEqual(p.detect_insecure_repo_settings("apt", text), [])

    def test_apt_boolean_spellings(self):
        for value in ("yes", "true", "on", "with", "enable", "1", "YES", "True"):
            self.assertEqual(p.detect_insecure_repo_settings("apt", f"deb [trusted={value}] http://x s m"),
                             ["APT_TRUSTED_YES"], value)
        for value in ("no", "false", "off", "0", "yesterday", "1a"):
            self.assertEqual(p.detect_insecure_repo_settings("apt", f"deb [trusted={value}] http://x s m"), [], value)

    def test_dnf_repo(self):
        self.assertEqual(p.detect_insecure_repo_settings("dnf", self.DNF_REPO), ["DNF_GPGCHECK_OFF", "DNF_SSLVERIFY_OFF"])

    def test_dnf_all_keys_and_spellings(self):
        text = "GPGCheck=No\nrepo_gpgcheck=off\nlocalpkg_gpgcheck=false\nsslverify=0\n"
        self.assertEqual(p.detect_insecure_repo_settings("dnf", text),
                         ["DNF_GPGCHECK_OFF", "DNF_LOCALPKG_GPGCHECK_OFF", "DNF_REPO_GPGCHECK_OFF", "DNF_SSLVERIFY_OFF"])

    def test_dnf_negatives(self):
        text = "gpgcheck=1\nsslverify=true\ngpgcheck=0 # inline comments are not INI\ngpgcheck=00\nmygpgcheck=0\n"
        self.assertEqual(p.detect_insecure_repo_settings("dnf", text), [])

    def test_pacman_sections_and_comments(self):
        self.assertEqual(p.detect_insecure_repo_settings("pacman", self.PACMAN), ["PACMAN_SIGLEVEL_OPTIONAL", "PACMAN_TRUSTALL"])

    def test_pacman_never_variants(self):
        self.assertEqual(p.detect_insecure_repo_settings("pacman", "SigLevel = Never"), ["PACMAN_SIGLEVEL_NEVER"])
        self.assertEqual(p.detect_insecure_repo_settings("pacman", "SigLevel = PackageRequired DatabaseNever"),
                         ["PACMAN_SIGLEVEL_NEVER"])
        self.assertEqual(p.detect_insecure_repo_settings("pacman", "SigLevel = Required PackageTrustAll"), ["PACMAN_TRUSTALL"])
        self.assertEqual(p.detect_insecure_repo_settings("pacman", "SigLevel = Required DatabaseOptional"), [])
        self.assertEqual(p.detect_insecure_repo_settings("pacman", "SigLevel = Required TrustedOnly"), [])
        # pacman keys are case-sensitive: this line is rejected by pacman itself.
        self.assertEqual(p.detect_insecure_repo_settings("pacman", "siglevel = never"), [])
        self.assertEqual(p.detect_insecure_repo_settings("pacman", "LocalFileSigLevel = Never"), [])

    def test_apk(self):
        text = "https://dl-cdn.alpinelinux.org/alpine/v3.20/main\n# --allow-untrusted\napk add --allow-untrusted x\n"
        self.assertEqual(p.detect_insecure_repo_settings("apk", text), ["APK_ALLOW_UNTRUSTED"])
        self.assertEqual(p.detect_insecure_repo_settings("apk", "https://dl-cdn.alpinelinux.org/alpine/v3.20/main\n"), [])

    def test_unknown_manager_and_empty(self):
        self.assertEqual(p.detect_insecure_repo_settings("zypper", "gpgcheck=0\nSigLevel = Never"), [])
        for name in ("apt", "dnf", "pacman", "apk"):
            self.assertEqual(p.detect_insecure_repo_settings(name, ""), [])

    def test_line_bound(self):
        text = "\n" * p.REPO_MAX_LINES + "gpgcheck=0\n"
        self.assertEqual(p.detect_insecure_repo_settings("dnf", text), [])
        text = "\n" * (p.REPO_MAX_LINES - 1) + "gpgcheck=0\n"
        self.assertEqual(p.detect_insecure_repo_settings("dnf", text), ["DNF_GPGCHECK_OFF"])


if HAVE_HYPOTHESIS:
    # Strategy names exist only when Hypothesis imported; the classes live inside the guard
    # so the module (and the packaged self-test) imports cleanly without it.
    @unittest.skipUnless(HAVE_HYPOTHESIS, "hypothesis not installed")
    class PackageParserProperties(unittest.TestCase):
        """Totality, closed vocabularies and conservation laws over arbitrary input."""

        @given(any_bytes)
        def test_mtree_total_and_keys_closed(self, raw):
            entries, stats = p.parse_pacman_mtree(raw)
            self.assertEqual(set(stats), {"lines", "malformed", "truncated"})
            self.assertLessEqual(stats["malformed"], stats["lines"])
            self.assertLessEqual(stats["lines"], p.MTREE_MAX_LINES)
            self.assertFalse(stats["truncated"])
            self.assertLessEqual(len(entries), stats["lines"])
            for path, attrs in entries.items():
                self.assertTrue(path.startswith("/"), path)
                self.assertTrue(set(attrs) <= p.MTREE_KEYS, attrs)
                if "type" in attrs:
                    self.assertIn(attrs["type"], p.MTREE_TYPES)
                if "mode" in attrs:
                    self.assertTrue(0 <= attrs["mode"] <= 0o7777)

        @given(st.lists(path_part, min_size=1, max_size=4), st.integers(0, 0o7777), st.integers(0, 65535), st.integers(0, 65535))
        def test_mtree_set_defaults_are_inherited_then_overridden(self, parts, mode, uid, gid):
            path = "/" + "/".join(parts)
            raw = f"/set type=file uid={uid} gid={gid} mode={mode:o}\n.{path} size=7\n./over mode=600\n".encode()
            entries, stats = p.parse_pacman_mtree(raw)
            self.assertEqual(stats["malformed"], 0)
            self.assertEqual(entries[path], {"type": "file", "uid": uid, "gid": gid, "mode": mode, "size": 7})
            self.assertEqual(entries["/over"]["mode"], 0o600)

        @given(any_bytes)
        def test_apk_total_and_keys_closed(self, raw):
            db, stats = p.parse_apk_installed(raw)
            self.assertEqual(set(db), {"packages", "files"})
            self.assertEqual(set(stats), {"lines", "malformed", "truncated"})
            self.assertLessEqual(stats["malformed"], stats["lines"] + 1)
            names = {pkg["name"] for pkg in db["packages"]}
            for path, info in db["files"].items():
                self.assertTrue(path.startswith("/") and "//" not in path, path)
                self.assertTrue(set(info) <= p.APK_FILE_KEYS, info)
                self.assertIn(info["package"], names)
            self.assertEqual(sum(pkg["files"] for pkg in db["packages"]) >= len(db["files"]), True)

        @given(any_text)
        def test_rpm_counts_every_nonblank_line_exactly_once(self, text):
            review = p.rpm_verify_review(text)
            nonblank = sum(1 for line in text.splitlines() if line.split())
            self.assertEqual(sum(review[k] for k in p.RPM_REVIEW_COUNTERS), nonblank)
            self.assertLessEqual(len(review["missing_by_prefix"]), 10)
            self.assertLessEqual(sum(review["missing_by_prefix"].values()), review["missing_files"])

        @given(rpm_column, rpm_type, st.lists(path_part, min_size=1, max_size=4))
        def test_rpm_attribute_line_classification_is_exhaustive(self, column, marker, parts):
            line = f"{column}  {marker or ' '} /{'/'.join(parts)}"
            review = p.rpm_verify_review(line)
            if column[2] == "5":
                key = "content_changed_conffiles" if marker == "c" else "content_changed_other_files"
            elif "?" in column:
                key = "unverifiable"
            elif column.strip("."):
                key = "metadata_changed_only"
            else:
                key = "unparsed_lines"
            self.assertEqual(review[key], 1, (line, review))

        @given(manager, any_text)
        def test_repo_settings_sorted_closed_subset(self, name, text):
            codes = p.detect_insecure_repo_settings(name, text)
            self.assertEqual(codes, sorted(set(codes)))
            self.assertTrue(set(codes) <= p.REPO_SETTING_CODES, codes)
            if name not in ("apt", "dnf", "pacman", "apk"):
                self.assertEqual(codes, [])

        @given(manager, st.lists(st.text(ONE_LINE, max_size=80), max_size=20))
        def test_fully_commented_input_yields_nothing(self, name, lines):
            hashed = "\n".join("#" + line for line in lines)
            self.assertEqual(p.detect_insecure_repo_settings(name, hashed), [])
            if name == "dnf":
                self.assertEqual(p.detect_insecure_repo_settings(name, "\n".join(";" + line for line in lines)), [])

        @given(st.lists(st.text(ONE_LINE, max_size=80), max_size=20))
        def test_apt_conf_comment_forms_are_inert(self, lines):
            slashed = "\n".join("// " + line for line in lines)
            self.assertEqual(p.detect_insecure_repo_settings("apt", slashed), [])
            blocked = "/*\n" + "\n".join(line.replace("*/", "") for line in lines) + "\n*/\n"
            self.assertEqual(p.detect_insecure_repo_settings("apt", blocked), [])

        @given(any_text)
        def test_detect_managers_total_on_arbitrary_relative_root(self, name):
            with tempfile.TemporaryDirectory() as tmp:
                result = p.detect_managers(Path(tmp) / name.replace("\x00", "").replace("/", "_"))
                self.assertEqual(result, [])



if __name__ == "__main__":  # pragma: no cover
    unittest.main()
