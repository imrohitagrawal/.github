#!/usr/bin/env bash
# test-public-content-tar-records.sh - every header record of a tar is read: the extension
# headers that carry a member's metadata (a pax 'x' header, a global pax 'g' header, a GNU 'L'
# long name or 'K' long link target) as well as the member's own header. Their data is read as
# content, and the padding after it must be NUL bytes, as a member's padding must. It shares the
# harness in lib-public-content-test.sh with the other public-content suites.
#
# Runs on bash 3.2 and 5, macOS and Linux, against throwaway files under mktemp, with the REAL
# gitleaks from PATH. The leak is ASSEMBLED AT RUN TIME (the fixture generator reads it from the
# environment), so this file holds no home path in a form a scanner would match. The bsdtar case
# is skipped when bsdtar is missing.
#
# ================================ CONTRACT (tar header records) ============================
#
# A tar is a run of records. Each is a 512-byte header with a valid checksum, then its data,
# then NUL bytes up to the next 512 boundary. An extension header's data length is its own size
# field; a member header's is the member's size. A byte other than NUL in any record's padding,
# or a record whose data runs past the end of the file, is exit 2 with `could not check`. The
# data of an extension header (pax records, GNU long names and link targets) is read as a file
# of its own, so a leak there is found (exit 1) even when the archive's printable runs split it.
# Archives that common tools write (GNU long names, pax non-ASCII names, pax global headers,
# bsdtar pax, gzip'd pax tars like npm's, GNU long link targets) pass (exit 0).
# Exit status as everywhere: 0 clean, 1 findings, 2 error.
# ===========================================================================================

# shellcheck source=scripts/lib-public-content-test.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib-public-content-test.sh"

echo "test-public-content-tar-records.sh"

FX="$WORK/tr"
mkdir -p "$FX"

L_H="$HOMEP" "$REAL_PY" -I - "$FX" <<'PY' || die "fixture generator failed"
# One archive per case. A hidden blob is a gzip of the leak, put in a header's padding after one
# NUL byte: tarfile stops reading a header's records at a NUL, so the archive still opens.
import gzip
import io
import os
import sys
import tarfile

OUT = sys.argv[1]
HOME = os.environ["L_H"]
LEAK = "see " + HOME + "\n"
BLOB = gzip.compress(LEAK.encode(), mtime=0)
CLEAN = b"All tests pass.\n"
# The leak with a non-ASCII letter right after the home folder prefix (the prefix, then an
# e-acute, then the name): the archive's 7-bit printable runs end at the prefix and restart at
# the name, so neither run is a home path; the UTF-8 text of the record still is one.
CUT = HOME.index("/", 1) + 1
SPLIT = "see " + HOME[:CUT] + "\u00e9" + HOME[CUT:]
# Member data that is not UTF-8, so the archive as a whole is not UTF-8 either and is read only
# through its printable runs (no whole-file view holds the split path).
BINARY = b"binary \xff\xfe\x00 data\n"


def write(name, data):
    with open(os.path.join(OUT, name), "wb") as f:
        f.write(data)


def tar(fmt, members, headers=None):
    """members: (TarInfo, data or None)."""
    b = io.BytesIO()
    kw = {"pax_headers": headers} if headers else {}
    with tarfile.open(fileobj=b, mode="w", format=fmt, **kw) as t:
        for info, data in members:
            if data is None:
                t.addfile(info)
            else:
                info.size = len(data)
                t.addfile(info, io.BytesIO(data))
    return bytearray(b.getvalue())


def member(name, pax=None):
    m = tarfile.TarInfo(name)
    if pax:
        m.pax_headers = pax
    return m


def link(name, target):
    m = tarfile.TarInfo(name)
    m.type = tarfile.SYMTYPE
    m.linkname = target
    return m


def size_of(g, at=0):
    return int(bytes(g[at + 124:at + 136]).split(b"\0")[0].strip(b" "), 8)


def first_type(g):
    return bytes(g[156:157])


def checksum(g, at=0):
    blk = g[at:at + 512]
    blk[148:156] = b" " * 8
    g[at + 148:at + 156] = b"%06o\0 " % sum(blk)


def hide(g, what, blob=BLOB):
    """A copy of G with BLOB in the padding of the header at 0, after one NUL (G is unchanged:
    the clean archives below are the same bytes without the blob)."""
    g = bytearray(g)
    size = size_of(g)
    assert size % 512 and size % 512 + 1 + len(blob) <= 512, what + ": no room in the padding"
    g[512 + size + 1:512 + size + 1 + len(blob)] = blob
    return bytes(g)


NONASCII = "\u00e9" * 10 + ".txt"
LONG = "n" * 120 + ".txt"
TARGET = "t" * 120 + ".txt"

# --- exit 2: a hidden gzip in an extension header's padding
x = tar(tarfile.PAX_FORMAT, [(member(NONASCII), CLEAN)])
assert first_type(x) == b"x"
write("xpad.tar", hide(x, "x"))
g = tar(tarfile.PAX_FORMAT, [(member("a.txt"), CLEAN)], {"comment": "clean"})
assert first_type(g) == b"g"
write("gpad.tar", hide(g, "g"))
ll = tar(tarfile.GNU_FORMAT, [(member(LONG), CLEAN)])
assert first_type(ll) == b"L"
write("lpad.tar", hide(ll, "L"))
k = tar(tarfile.GNU_FORMAT, [(link("ln", TARGET), None)])
assert first_type(k) == b"K"
write("kpad.tar", hide(k, "K"))
# One stray byte at the end of an 'x' header's padding (the rest NUL).
s = tar(tarfile.PAX_FORMAT, [(member(NONASCII), CLEAN)])
assert size_of(s) < 511
s[1023] = ord("Z")
write("xstray.tar", bytes(s))
# An 'x' header whose size field (checksum fixed) says its data runs past the end of the file.
p = tar(tarfile.PAX_FORMAT, [(member(NONASCII), CLEAN)])
p[124:136] = b"%011o\0" % (1 << 20)
checksum(p)
assert len(p) < (1 << 20)
write("xpast.tar", bytes(p))

# --- exit 1: a leak in a pax record that the archive's printable runs do not hold
d = tar(tarfile.PAX_FORMAT, [(member("a.bin", {"comment": SPLIT}), BINARY)])
assert first_type(d) == b"x"
assert SPLIT.encode() in d and HOME.encode() not in d
try:
    bytes(d).decode("utf-8")
    raise SystemExit("xdirty.tar must not be UTF-8 as a whole")
except UnicodeDecodeError:
    pass
write("xdirty.tar", bytes(d))
gd = tar(tarfile.PAX_FORMAT, [(member("a.bin"), BINARY)], {"comment": SPLIT})
assert first_type(gd) == b"g"
write("gdirty.tar", bytes(gd))

# --- exit 0: archives as common tools write them
xc = tar(tarfile.PAX_FORMAT, [(member("a.bin", {"comment": "clean metadata"}), BINARY)])
write("xclean.tar", bytes(xc))
for clean in (ll, x, k):
    assert BLOB not in clean and not bytes(clean[512 + size_of(clean):1024]).strip(b"\0")
write("gnu-long.tar", bytes(ll))
write("pax-nonascii.tar", bytes(x))
pg = tar(tarfile.PAX_FORMAT, [(member("a.txt"), CLEAN), (member("b.txt"), CLEAN)],
         {"comment": "clean metadata", "note": "two"})
write("pax-global.tar", bytes(pg))
write("gnu-longlink.tar", bytes(k))
npm = tar(tarfile.PAX_FORMAT, [(member("package/package.json"), b'{"name": "demo"}\n'),
                               (member("package/" + "deep/" * 22 + "index.js"), b"exports.a = 1;\n")])
assert b" path=package/deep/" in npm, "the long path must be in a pax record"
write("npm.tgz", gzip.compress(bytes(npm), mtime=0))
PY

if command -v bsdtar >/dev/null 2>&1; then
  BSD="$FX/bsd"
  LONGDIR="$BSD/package/$(printf 'deep/%.0s' 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21)"
  mkdir -p "$LONGDIR"
  printf 'All tests pass.\n' >"$LONGDIR/index.js"
  printf 'All tests pass.\n' >"$BSD/package/$(printf '\303\251t\303\251.txt')"
  # One path part of 110 characters: longer than the ustar name field, so it needs a path record.
  printf 'All tests pass.\n' >"$BSD/package/$(printf '%0110d' 0 | tr 0 n).txt"
  (cd "$BSD" && bsdtar -cf - --format pax package) >"$FX/bsdtar-pax.tar" || die "bsdtar failed"
fi

_bin() { _run python3 "$SCAN" text --label demo <"$1"; }
# tcase NAME FILE WANT [NEEDLE...]: text mode. WANT 0 (clean, gitleaks ran), 1 (the home path
# found) or 2 (refused, with `could not check`). The split leak's name part must not be shown.
tcase() {
  local name="$1" file="$2" want="$3"
  shift 3
  _bin "$FX/$file"
  if grep -q -F -e "jane/notes" "$OUT" "$ERR"; then
    bad "$name" "the output repeats the matched text"
    return
  fi
  case "$want" in
    0) expect_rc "$name" 0 @scanned "$@" ;;
    1) expect_rc "$name" 1 home-folder-path "$@" ;;
    2) expect_rc "$name" 2 "could not check" "$@" ;;
    *) die "tcase: bad want $want" ;;
  esac
}

echo "== bytes hidden in an extension header's padding"
# RED WHEN: a pax 'x' header's padding is not checked (tarfile folds the header into its member).
tcase "tar records: a gzip hidden in a pax 'x' header's padding -> exit 2" xpad.tar 2 "padding"
# RED WHEN: a global pax 'g' header's padding is not checked.
tcase "tar records: a gzip hidden in a global 'g' header's padding -> exit 2" gpad.tar 2 "padding"
# RED WHEN: a GNU 'L' long-name header's padding is not checked.
tcase "tar records: a gzip hidden in a GNU 'L' header's padding -> exit 2" lpad.tar 2 "padding"
# RED WHEN: a GNU 'K' long-link header's padding is not checked.
tcase "tar records: a gzip hidden in a GNU 'K' header's padding -> exit 2" kpad.tar 2 "padding"
# RED WHEN: an extension header's padding is checked only for a hidden stream, not for any byte.
tcase "tar records: one stray byte in a pax 'x' header's padding -> exit 2" xstray.tar 2 "padding"
# RED WHEN: an extension header whose data runs past the end of the file is read as far as it goes.
tcase "tar records: a pax 'x' header whose size runs past the end -> exit 2" xpast.tar 2

echo "== the data of an extension header is read as content"
# RED WHEN: a pax 'x' header's records are not read as a file of their own. Nothing else keeps it
# green: the archive is not UTF-8 (no whole-file view), and its 7-bit printable runs are split at
# the non-ASCII letter after the home folder prefix, so neither run is a home path.
tcase "tar records: a home path in a pax 'x' record is found" xdirty.tar 1
# RED WHEN: a global 'g' header's records are not read as a file of their own (same split leak).
tcase "tar records: a home path in a global 'g' record is found" gdirty.tar 1

echo "== archives from common tools pass"
# RED WHEN: a pax 'x' header's records are scanned as something that can never be clean, or a
# member after an 'x' header is refused (partner of the 'x' record case above).
tcase "tar records: a pax tar with a clean comment record passes" xclean.tar 0
# RED WHEN: a GNU 'L' header counts as bytes between members, or its data length is misread.
tcase "tar records: a GNU tar with a 120-character name passes" gnu-long.tar 0
# RED WHEN: a pax 'x' header (a non-ASCII name) counts as bytes between members.
tcase "tar records: a pax tar with a non-ASCII name passes" pax-nonascii.tar 0
# RED WHEN: a global header before the first member is refused.
tcase "tar records: a pax tar with a global header passes" pax-global.tar 0
# RED WHEN: a GNU 'K' header (a symlink's long target) counts as bytes between members.
tcase "tar records: a GNU tar with a long symlink target passes" gnu-longlink.tar 0
# RED WHEN: a gzip'd pax tar with a long path (as npm packs) is refused.
tcase "tar records: a gzip'd pax tar with a long path passes" npm.tgz 0
if [ -f "$FX/bsdtar-pax.tar" ]; then
  # RED WHEN: the extension headers bsdtar writes (pax records for long and non-ASCII paths,
  # times and, on macOS, extended attributes, besides AppleDouble members) are refused.
  tcase "tar records: a bsdtar pax archive passes" bsdtar-pax.tar 0
else
  skip "tar records: a bsdtar pax archive passes" "no bsdtar"
fi

echo
echo "${PASS} passed, ${FAIL} failed, ${SKIPPED} skipped"
[ "$FAIL" -eq 0 ]
