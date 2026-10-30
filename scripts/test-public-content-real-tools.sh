#!/usr/bin/env bash
# test-public-content-real-tools.sh - archives written the way common tools write them must be
# read, not refused: Info-ZIP's data-descriptor zips (which keep the sizes they know in the local
# header) and Python's pax tars with a global header (which tarfile reads without returning it as
# a member). A global header's records are read as content too. It shares the harness in
# lib-public-content-test.sh with the other public-content suites.
#
# Runs on bash 3.2 and 5, macOS and Linux, against throwaway files under mktemp, with the REAL
# gitleaks from PATH. The leak is ASSEMBLED AT RUN TIME (the fixture generator reads it from the
# environment), so this file holds no home path in a form a scanner would match. Cases that need
# the `zip` tool are skipped when it is missing.
#
# Exit status as everywhere: 0 clean, 1 findings, 2 error.

# shellcheck source=scripts/lib-public-content-test.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib-public-content-test.sh"

echo "test-public-content-real-tools.sh"

FX="$WORK/rt"
mkdir -p "$FX"
printf 'All tests pass.\n' >"$FX/clean.txt"
printf 'see %s\n' "$HOMEP" >"$FX/dirty.txt"

L_H="$HOMEP" "$REAL_PY" -I - "$FX" <<'PY' || die "fixture generator failed"
import io
import os
import sys
import tarfile

OUT = sys.argv[1]
LEAK = "see " + os.environ["L_H"]


def pax(name, headers, members):
    b = io.BytesIO()
    with tarfile.open(fileobj=b, mode="w", format=tarfile.PAX_FORMAT, pax_headers=headers) as t:
        for mname, data in members:
            m = tarfile.TarInfo(mname)
            m.size = len(data)
            t.addfile(m, io.BytesIO(data))
    with open(os.path.join(OUT, name), "wb") as f:
        f.write(b.getvalue())
    return b.getvalue()


pax("gpax-clean.tar", {"comment": "clean metadata"}, [("a.txt", b"All tests pass.\n")])
pax("gpax-dirty-member.tar", {"comment": "clean metadata"}, [("a.txt", LEAK.encode() + b"\n")])
pax("gpax-dirty-header.tar", {"comment": LEAK}, [("a.txt", b"All tests pass.\n")])
# Two members with one stray 512-byte block of text between them.
raw = bytearray(pax("two.tar", {}, [("a.txt", b"one\n"), ("b.txt", b"two\n")]))
second = 1024  # the first member: one header block and one data block
gap = bytes(raw[:second]) + b"stray text, not a tar header".ljust(512, b"\0") + bytes(raw[second:])
with open(os.path.join(OUT, "gap.tar"), "wb") as f:
    f.write(gap)
# A global header whose padding hides a gzip of the leak after its (clean) records.
import gzip
g = bytearray(pax("gpad.tar", {"comment": "clean"}, [("a.txt", b"All tests pass.\n")]))
size = int(bytes(g[124:136]).split(b"\0")[0].strip(b" "), 8)
blob = gzip.compress(LEAK.encode())
assert size + 1 + len(blob) <= 512, "the hidden blob must fit in the header's padding"
# One NUL first: tarfile stops reading a header's records at a NUL, so it still opens.
g[512 + size + 1:512 + size + 1 + len(blob)] = blob
with open(os.path.join(OUT, "gpad.tar"), "wb") as f:
    f.write(bytes(g))
PY

_bin() { _run python3 "$SCAN" text --label demo <"$1"; }
# tcase NAME FILE WANT [NEEDLE...]: text mode. WANT 0 (clean, gitleaks ran), 1 (the home path
# found) or 2 (refused, with `could not check`).
tcase() {
  local name="$1" file="$2" want="$3"
  shift 3
  _bin "$FX/$file"
  case "$want" in
    0) expect_rc "$name" 0 @scanned "$@" ;;
    1) expect_rc "$name" 1 home-folder-path "$@" ;;
    2) expect_rc "$name" 2 "could not check" "$@" ;;
    *) die "tcase: bad want $want" ;;
  esac
}

echo "== Info-ZIP data-descriptor zips"
if command -v zip >/dev/null 2>&1; then
  (cd "$FX" && zip -q -fd fd-clean.zip clean.txt && zip -q -fd fd-dirty.zip dirty.txt)
  (cd "$FX" && zip -q - clean.txt >pipe-clean.zip)
  # RED WHEN: a descriptor zip's local header must hold zero sizes (Info-ZIP writes the known ones).
  tcase "real tools: an Info-ZIP zip written with data descriptors passes" fd-clean.zip 0
  # RED WHEN: descriptor zips are passed without reading their entries.
  tcase "real tools: a home path in an Info-ZIP data-descriptor zip is found" fd-dirty.zip 1
  # RED WHEN: a zip Info-ZIP streams to a pipe is refused.
  tcase "real tools: an Info-ZIP zip written to a pipe passes" pipe-clean.zip 0
else
  skip "real tools: Info-ZIP cases" "no zip tool"
fi

echo "== xar archives (compressed members the guard cannot open)"
if command -v bsdtar >/dev/null 2>&1 && (cd "$FX" && bsdtar -cf clean.xar --format xar clean.txt) 2>/dev/null; then
  # RED WHEN: a xar archive (zlib-compressed members, signature "xar!") passes unread instead of blocking.
  tcase "real tools: a xar archive is refused, naming the format" clean.xar 2 "xar"
else
  skip "real tools: xar case" "no bsdtar with xar support"
fi

echo "== pax tars with a global header"
# RED WHEN: a global pax header counts as bytes between members.
tcase "real tools: a pax tar with a global header passes" gpax-clean.tar 0
# RED WHEN: the member after a global header is not read.
tcase "real tools: a home path in a member after a global header is found" gpax-dirty-member.tar 1
# RED WHEN: a global header's text is checked neither as content nor through the archive's own
# printable text (each alone keeps this case green: reading the records is a second line).
tcase "real tools: a home path in a global header's records is found" gpax-dirty-header.tar 1
# RED WHEN: a global header's padding is not required to be NUL (a gzip hidden there is unread).
tcase "real tools: bytes hidden in a global header's padding -> exit 2" gpad.tar 2 "padding"
# RED WHEN: bytes between two tar members are passed instead of refused.
tcase "real tools: a stray block between two tar members -> exit 2" gap.tar 2

echo
echo "${PASS} passed, ${FAIL} failed, ${SKIPPED} skipped"
[ "$FAIL" -eq 0 ]
