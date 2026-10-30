#!/usr/bin/env bash
# test-public-content-zip-headers.sh - the public-content scanner checks each zip entry's local
# header against its central directory entry. A reader that walks local headers (a streaming
# unzip) and one that reads the central directory must see the same entries, or the guard could
# check one set of files while another tool unpacks a different one. It shares the harness in
# lib-public-content-test.sh with the other public-content suites.
#
# Runs on bash 3.2 and 5, macOS and Linux, against throwaway files under mktemp, with the REAL
# gitleaks from PATH. The leak is ASSEMBLED AT RUN TIME (the fixture generator reads it from the
# environment), so this file holds no home path in a form a scanner would match.
#
# =================================== CONTRACT (zip headers) =================================
#
# A zip entry's local header must agree with its central directory entry: the same file name,
# method and flag bit 3; without bit 3, the same CRC-32, compressed and uncompressed sizes
# (0xFFFFFFFF resolved from the zip64 extra field); with bit 3 (the values follow in the data
# descriptor), each of the CRC and sizes either 0 or the directory's value, as Info-ZIP writes
# the sizes it knows. Otherwise exit 2 with `could not check`, naming the
# file and saying what to do. Exit status as everywhere: 0 clean, 1 findings, 2 error.
# ===========================================================================================

# shellcheck source=scripts/lib-public-content-test.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib-public-content-test.sh"

echo "test-public-content-zip-headers.sh"

FX="$WORK/zh"
mkdir -p "$FX"
L_H="$HOMEP" "$REAL_PY" -I - "$FX" <<'PY' || die "fixture generator failed"
# One zip per case, built record by record so a single local header field can differ from the
# central directory. Writes sanity.txt (`ok|bad description`).
import io
import os
import struct
import sys
import zipfile
import zlib

OUT = sys.argv[1]
LEAK = b"see " + os.environ["L_H"].encode() + b"\n"
CLEAN = b"All tests pass.\n"
SANITY = []


def deflate(d):
    c = zlib.compressobj(9, zlib.DEFLATED, -15)
    return c.compress(d) + c.flush()


def build(data, local_name=None, local_crc=None, local_usize=None, desc=False):
    """A one-entry deflate zip named a.md. local_*: what the LOCAL header says instead of the
    true value (the central directory always holds the true values). desc: flag bit 3 with a
    signed 16-byte data descriptor; the local CRC and sizes are 0 unless overridden."""
    name = b"a.md"
    comp = deflate(data)
    crc, csize, usize = zlib.crc32(data), len(comp), len(data)
    flags = 8 if desc else 0
    lcrc, lcs, lus = (0, 0, 0) if desc else (crc, csize, usize)
    if local_crc is not None:
        lcrc = local_crc
    if local_usize is not None:
        lus = local_usize
    lname = local_name or name
    out = struct.pack("<4sHHHHHIIIHH", b"PK\x03\x04", 20, flags, 8, 0, 0x21, lcrc, lcs, lus, len(lname), 0)
    out += lname + comp
    if desc:
        out += struct.pack("<4sIII", b"PK\x07\x08", crc, csize, usize)
    cd = struct.pack("<4sHHHHHHIIIHHHHHII", b"PK\x01\x02", 20, 20, flags, 8, 0, 0x21, crc, csize, usize,
                     len(name), 0, 0, 0, 0, 0, 0) + name
    return out + cd + struct.pack("<4sHHHHIIH", b"PK\x05\x06", 0, 0, 1, 1, len(cd), len(out), 0)


def w(fname, data):
    with open(os.path.join(OUT, fname), "wb") as f:
        f.write(data)


def opens(data):
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            return {i.filename: z.read(i) for i in z.infolist()}
    except Exception:  # noqa: BLE001 - a sanity probe
        return None


good = build(CLEAN)
w("clean.zip", good)
SANITY.append(("ok" if opens(good) == {"a.md": CLEAN} else "bad") + " the clean partner opens with Python's zipfile")
w("leak.zip", build(LEAK))
w("desc-clean.zip", build(CLEAN, desc=True))
SANITY.append(("ok" if opens(build(CLEAN, desc=True)) == {"a.md": CLEAN} else "bad") + " the bit-3 partner opens")
for fname, data in (("name.zip", build(CLEAN, local_name=b"b.md")),
                    ("size.zip", build(CLEAN, local_usize=len(CLEAN) + 1)),
                    ("crc.zip", build(CLEAN, local_crc=zlib.crc32(CLEAN) ^ 1)),
                    ("desc-crc.zip", build(CLEAN, desc=True, local_crc=zlib.crc32(CLEAN) ^ 1)),
                    ("desc-known.zip", build(CLEAN, desc=True, local_crc=zlib.crc32(CLEAN), local_usize=len(CLEAN)))):
    w(fname, data)
    # Each differs from its partner in exactly the four bytes (or fewer) of one local field.
    base = build(CLEAN, desc=fname.startswith("desc"))
    diff = sum(1 for a, b in zip(base, data) if a != b)
    SANITY.append(("ok" if len(base) == len(data) and 0 < diff <= (8 if fname == "desc-known.zip" else 4) else "bad")
                  + " %s differs from its partner in one local header field only" % fname)
with open(os.path.join(OUT, "sanity.txt"), "w") as f:
    f.write("\n".join(SANITY) + "\n")
PY

echo "== sanity: the fixtures are what the cases say"
# RED WHEN: a fixture stops differing from its partner in exactly one local header field, so a
# case below would pass for another reason.
while read -r verdict what; do
  [ -n "$verdict" ] || continue
  if [ "$verdict" = ok ]; then ok "sanity: $what"; else bad "sanity: $what" "fixture is not what the case needs"; fi
done <"$FX/sanity.txt"

_bin() { _run python3 "$SCAN" text --label demo <"$1"; }
# zcase NAME FILE WANT [NEEDLE...]: text mode. WANT 0 (clean, gitleaks ran), 1 (the home path
# found) or 2 (refused, with `could not check`).
zcase() {
  local name="$1" file="$2" want="$3"
  shift 3
  _bin "$FX/$file"
  case "$want" in
    0) expect_rc "$name" 0 @scanned "$@" ;;
    1) expect_rc "$name" 1 home-folder-path "$@" ;;
    2) expect_rc "$name" 2 "could not check" "$@" ;;
    *) die "zcase: bad want $want" ;;
  esac
}

echo "== local headers must agree with the central directory"
# RED WHEN: the header check refuses consistent zips (partners of every case below).
zcase "zip headers: a consistent entry passes" clean.zip 0
zcase "zip headers: a consistent entry with flag bit 3 and zero local values passes" desc-clean.zip 0
# RED WHEN: the entry is no longer read at all (the refusals below would prove nothing).
zcase "zip headers: a home path in a consistent entry is found" leak.zip 1 "inside the archive"
# RED WHEN: the local file name is not compared with the central directory's.
zcase "zip headers: a local name that differs from the directory -> exit 2" name.zip 2 "local header" demo
# RED WHEN: the local sizes are not compared when flag bit 3 is clear.
zcase "zip headers: a local size that differs from the directory -> exit 2" size.zip 2 "local header"
# RED WHEN: the local CRC is not compared when flag bit 3 is clear.
zcase "zip headers: a local CRC that differs from the directory -> exit 2" crc.zip 2 "local header"
# RED WHEN: with flag bit 3 set, a local CRC that is neither 0 nor the directory's is accepted.
zcase "zip headers: flag bit 3 with a local CRC that differs from the directory -> exit 2" desc-crc.zip 2 "local header"
# RED WHEN: with flag bit 3 set, local values must all be 0 (Info-ZIP's descriptor zips then block).
zcase "zip headers: flag bit 3 with the true CRC and size in the local header passes" desc-known.zip 0

echo "== CI mode names the file and says what to do"
FR="$WORK/zci"
git init -q "$FR"
commit_file "$FR" a.txt "start" "init"
FRBASE="$(git -C "$FR" rev-parse HEAD)"
mkdir -p "$FR/pkg"
cp "$FX/name.zip" "$FR/pkg/bundle.zip"
if ! { git -C "$FR" add pkg/bundle.zip && git -C "$FR" commit -q -m "add a bundle"; }; then die "commit"; fi
(unset PRIVATE_NOTES_DIR && PR_TITLE="Add a bundle" PR_BODY="Adds a bundle." \
  _run python3 "$SCAN" ci --repo "$FR" --base "$FRBASE" --head "$(git -C "$FR" rev-parse HEAD)")
# RED WHEN: CI accepts the mismatched zip, or its block does not name the file and what to do.
expect_rc "zip headers (ci): a mismatched local name is refused, naming the file and what to do" 2 \
  "could not check" pkg/bundle.zip "zip, tar.gz or tar.xz" "private repository"

echo
echo "${PASS} passed, ${FAIL} failed, ${SKIPPED} skipped"
[ "$FAIL" -eq 0 ]
