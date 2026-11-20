#!/usr/bin/env bash
# test-public-content-formats.sh - how the public-content scanner reads file formats: text that
# gitleaks would skip as a binary, archives (zip, tar, gzip, bzip2, xz) read completely or
# refused, UTF-16 and UTF-32 without a byte-order mark, other binaries, embedded repositories
# (gitlinks) and the one diff-tree call over all new commits. It uses
# lib-public-content-test.sh, the shared harness of the scripts/test-public-content-*.sh
# suites.
#
# The cases were written before the code they test, and each names the change that turns it
# red. Runs on bash 3.2 and 5, macOS and Linux, against throwaway files and repositories under
# mktemp, with the REAL gitleaks (8.30.1) from PATH. Every leak is ASSEMBLED AT RUN TIME (the
# fixture generator below reads it from the environment), so this file holds no home path,
# address, key or private term in a form a scanner would match. All names are fictional.
#
# =================================== CONTRACT (formats) ===================================
#
# Exit status as everywhere: 0 clean, 1 findings, 2 error. A case expecting 2 also expects the
# words `could not check` (a deliberate block, not a crash).
#
# (a) gitleaks skips a file it sniffs as a binary (h2non/filetype on the first read: `ustar` at
#     byte 257, `DICM` at 128, `CD001` at 32769), logged at DEBUG only. Every chunk ends with a
#     canary line only this run can know; a chunk counts as read only when its canary is
#     reported. A chunk with a `skipping` log line or a missing canary is written again behind
#     100 000 newlines and scanned once more; findings there keep their real line numbers. Still
#     skipped or still missing: exit 2. So text that only looks like a binary signature is read
#     (found or clean, never exit 2), and a gitleaks that silently drops a file blocks.
#     Log lines are read at debug level: WRN/ERR (other than `leaks found: N`) -> 2; a line not
#     of the shape `<time> <LEVEL> ...` -> 2; a `skipping` line naming a file that is not one of
#     this run's chunks -> 2; other TRC/DBG/INF lines are ignored.
#     A text longer than one gitleaks piece (100 000 bytes) is scanned as windows of at most
#     90 000 bytes overlapping by at least 14 000, edges moved back to a line start or a byte
#     that is not a letter or digit when one is near, each with its own canary. Key blocks (a
#     shorter header retried when the longest has no END marker, as Go does) and runs of
#     encoded text over 12 000 bytes (OVERLAP - 2 * EDGE, in the shapes gitleaks 8.30.1
#     decodes, up to 90 000 bytes) are also read whole, also where a window holds them: spans
#     that overlap are merged (spans that only touch are not), then packed in order into groups
#     of at most 90 000 bytes, each group starting at a merged span's start. In a merged span
#     over 90 000 bytes, its key blocks are grouped the same way and each of its encoded runs is
#     a piece of its own (such pieces may overlap). A key block over 90 000 bytes -> 2, naming
#     the place; a longer encoded run is read in the windows (never 2).
#     Private terms are matched on the whole text. Findings keep the text's line numbers.
# (b) A file that starts like a zip, tar, gzip, bzip2 or xz is read completely, or exit 2.
#     zip: one end record, ending exactly at the end of the file; entries back to back from byte
#     0 to the central directory (data descriptors of 12, 16, 20 or 24 bytes matched to the
#     directory); every entry read (directories too) with methods 0, 8 or 12 only; the decoder
#     at its end with no input left over, size and CRC equal. Anything else -> 2.
#     tar: found by a valid header checksum (after whole NUL blocks), not by `ustar`; members
#     back to back (a global pax header is stepped over and its records read as content);
#     after them NUL bytes or another tar; anything else -> 2; sparse -> 2.
#     gzip/bzip2/xz: stream after stream of the SAME format, NUL padding between and after;
#     any other byte -> 2. The number of streams is bounded only by the unpack limit (each
#     stream also costs 4 KB of it).
# (c) Anything holding a NUL also gets UTF-16 (LE and BE) and UTF-32 (LE and BE) printable-run
#     views, so text without a byte-order mark is read.
# (d) Archives the guard cannot open block (exit 2), clean or not: 7z, rar, zstd, lz4 frame,
#     lzip, Unix compress and Microsoft cabinet, found by their leading signature, at the start
#     of every file and of every file inside an archive. In every mode the block message names
#     the file and says what to do (remove it from the commits; commit it unpacked; repack it
#     as zip, tar.gz or tar.xz; or keep it in a private repository). Other binaries (images,
#     anything else holding a NUL): their printable runs of 12 or more characters are checked
#     (7-bit, UTF-16 and UTF-32), and the whole file when it is valid UTF-8; reported-speech
#     warnings are not raised from them.
#     A run counts from 12 characters; leaks below are planted as runs of 12+ characters, and
#     random binary data after an image header passes.
# (e) A gitlink (mode 160000) a new commit adds or changes: its path is a checked name; its
#     target commit is never read, so a target absent locally is no error.
# (f) One `git diff-tree --stdin` for all new commits gives the same files and names as one call
#     per commit: empty commits, merges, a path starting with `:` and a path that is itself a
#     commit sha in the range.
# ===========================================================================================

# shellcheck source=scripts/lib-public-content-test.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib-public-content-test.sh"

echo "test-public-content-formats.sh"

FX="$WORK/fmt"
mkdir -p "$FX"
L_H="$HOMEP" L_K="$KEY" L_M="$MAIL" "$REAL_PY" -I - "$FX" <<'PY' || die "fixture generator failed"
# Fixtures. Every leak comes from the environment (L_H a home path, L_K a key, L_M an
# address). Writes one file per case into the folder given, plus meta.txt (`name value`: line
# numbers) and sanity.txt (`ok|bad description`: proof that each fixture is what its case says,
# e.g. that Python's own zipfile is fooled, or that a leak is hidden from a raw read).
import bz2
import gzip
import io
import lzma
import os
import random
import struct
import sys
import tarfile
import zipfile
import zlib

OUT = sys.argv[1]
H = os.environ["L_H"].encode()
K = os.environ["L_K"].encode()
M = os.environ["L_M"].encode()
LEAK = b"see " + H + b"\n"
CLEAN = b"All tests pass.\n"
RND = random.Random(11)
META = []
SANITY = []


def w(name, data):
    with open(os.path.join(OUT, name), "wb") as f:
        f.write(data)


def check(what, cond):
    SANITY.append(("ok" if cond else "bad") + " " + what)


def gz(d):
    return gzip.compress(d, mtime=0)


def deflate(d):
    c = zlib.compressobj(9, zlib.DEFLATED, -15)
    return c.compress(d) + c.flush()


def hidden(name, data):
    """A fixture whose leak is only visible after unpacking: a raw read must not see it."""
    check("%s hides the leak from a raw read" % name, H not in data)
    w(name, data)


# ------------------------------------------------------------------ (a) sniffed text
def sniff_text(magic, at, leak_line):
    """Text (no NUL) with MAGIC at FILE byte AT (chunk byte AT + 1) and the leak alone on line
    LEAK_LINE (or no leak when LEAK_LINE is None). Returns the bytes."""
    head = b"# Header notes: this text only looks like a binary signature.\n"
    body = head
    while len(body) + 80 < at:
        body += b"y" * 79 + b"\n"
    body += b"z" * (at - len(body)) + magic + b" sits here in plain text\n"
    assert body[at:at + len(magic)] == magic and b"\0" not in body
    n = body.count(b"\n")
    body += b"more plain text\n"
    n += 1
    if leak_line is not None:
        while n + 1 < leak_line:
            body += b"filler\n"
            n += 1
        body += LEAK
    return body


for tag, magic, at in (("tar", b"ustar", 256), ("dicm", b"DICM", 127), ("iso", b"CD001", 32768)):
    w("sniff-%s.txt" % tag, sniff_text(magic, at, None))
    lines = sniff_text(magic, at, None).count(b"\n")
    dirty = sniff_text(magic, at, lines + 3)
    w("sniff-%s-leak.txt" % tag, dirty)
    META.append("sniff-%s-line %d" % (tag, dirty[:dirty.index(LEAK)].count(b"\n") + 1))

# A file gitleaks skips: a key, an address and a home path after `ustar` at byte 256.
line1 = b"# Tar header notes: the magic field sits at offset 257. Example of a header dump follows."
pad = b"x" * (256 - len(line1) - 1)
t9 = line1 + b"\n" + pad + b"ustar  \n" + b"aws_access_key_id = " + K + b"\ncontact " + M + b"\npath " + H + b"\n"
assert t9[256:261] == b"ustar"
w("t9-notes.md", t9)

# A commit message (or PR body) of the same shape: line 3 holds the leak.
msg = line1 + b"\n" + pad + b"ustar notes\n" + LEAK
assert msg[256:261] == b"ustar"
w("sniff-message.txt", msg)

# `ustar` at file byte 257 (the scanner's own old tar test), no valid checksum: plain text.
w("ustar257-leak.txt", b"A" * 257 + b"ustar " + LEAK)
w("ustar257-clean.txt", b"A" * 257 + b"ustar " + CLEAN)

# Marked text for the dropping gitleaks wrappers (the marker is on its own line).
w("marked-leak.txt", b"dropmarker-q7z\n" + LEAK)
w("marked-clean.txt", b"dropmarker-q7z\n" + CLEAN)
w("leak.txt", LEAK)
w("clean.txt", CLEAN)


# ------------------------------------------------------------------ (b) zip
def zip_build(entries, comment=b""):
    """A zip from hand-built records, so every field and byte can be placed. Each entry: name,
    data (uncompressed), method (0 stored, 8 deflate, 12 bzip2), comp (the stored bytes, when
    given), crc / usize (overrides), flags, desc (None or 12/16/20/24: a data descriptor of that
    length), desc_crc (override in the descriptor), after (bytes placed after the entry)."""
    out = bytearray()
    cd = bytearray()
    for e in entries:
        name = e["name"]
        data = e.get("data", b"")
        method = e.get("method", 8)
        comp = e.get("comp")
        if comp is None:
            comp = data if method == 0 else deflate(data) if method == 8 else bz2.compress(data)
        crc = e.get("crc", zlib.crc32(data))
        usize = e.get("usize", len(data))
        csize = len(comp)
        desc = e.get("desc")
        flags = e.get("flags", 0) | (8 if desc else 0)
        z64 = desc in (20, 24)
        version = 45 if z64 else 20
        if desc:
            lcrc, lcs, lus = 0, (0xFFFFFFFF if z64 else 0), (0xFFFFFFFF if z64 else 0)
        else:
            lcrc, lcs, lus = crc, csize, usize
        extra = struct.pack("<HHQQ", 1, 16, 0, 0) if z64 else b""
        off = len(out)
        out += struct.pack("<4sHHHHHIIIHH", b"PK\x03\x04", version, flags, method, 0, 0x21,
                           lcrc, lcs, lus, len(name), len(extra)) + name + extra + comp
        dcrc = e.get("desc_crc", crc)
        if desc == 12:
            out += struct.pack("<III", dcrc, csize, usize)
        elif desc == 16:
            out += struct.pack("<4sIII", b"PK\x07\x08", dcrc, csize, usize)
        elif desc == 20:
            out += struct.pack("<IQQ", dcrc, csize, usize)
        elif desc == 24:
            out += struct.pack("<4sIQQ", b"PK\x07\x08", dcrc, csize, usize)
        out += e.get("after", b"")
        attr = 0x10 if name.endswith(b"/") else 0
        cd += struct.pack("<4sHHHHHHIIIHHHHHII", b"PK\x01\x02", 20, version, flags, method, 0, 0x21,
                          crc, csize, usize, len(name), 0, 0, 0, 0, attr, off) + name
    cdoff = len(out)
    out += cd
    n = len(entries)
    out += struct.pack("<4sHHHHIIH", b"PK\x05\x06", 0, 0, n, n, len(cd), cdoff, len(comment)) + comment
    return bytes(out)


def zip_reads(data):
    """{name: content} as Python's zipfile reads DATA; None when it cannot."""
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            return {i.filename: z.read(i) for i in z.infolist()}
    except Exception:  # noqa: BLE001 - a sanity probe
        return None


def zip_py(members, compression=zipfile.ZIP_DEFLATED):
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w", compression=compression) as z:
        for n, d in members:
            z.writestr(n, d)
    return b.getvalue()


def zip_nonseek(members, z64):
    """What Python's zipfile writes to a pipe: data descriptors with a signature (16 bytes, or
    24 with force_zip64)."""
    buf = io.BytesIO()

    class Pipe(io.RawIOBase):
        def writable(self):
            return True

        def write(self, b):
            buf.write(b)
            return len(b)

    with zipfile.ZipFile(Pipe(), "w", compression=zipfile.ZIP_DEFLATED) as z:
        for n, d in members:
            with z.open(n, "w", force_zip64=z64) as f:
                f.write(d)
    return buf.getvalue()


ZA = zip_build([{"name": b"notes.md", "data": LEAK}])
ZB = zip_build([{"name": b"readme.md", "data": CLEAN}])
hidden("zip-concat.zip", ZA + ZB)
check("zip-concat.zip: Python's zipfile reads only the last zip", zip_reads(ZA + ZB) == {"readme.md": CLEAN})

w("zip-trail.zip", ZB + b"trailing text after the end record\n")
check("zip-trail.zip: Python's zipfile still opens it", zip_reads(ZB + b"trailing text after the end record\n") is not None)

two = deflate(CLEAN) + deflate(LEAK)
z = zip_build([{"name": b"readme.md", "data": CLEAN, "comp": two}])
hidden("zip-second-stream.zip", z)
check("zip-second-stream.zip: Python's zipfile reads only the first deflate stream", zip_reads(z) == {"readme.md": CLEAN})

z = zip_build([{"name": b"d/", "data": LEAK}, {"name": b"d/readme.md", "data": CLEAN}])
hidden("zip-dir-data.zip", z)
check("zip-dir-data.zip: the directory entry really holds the leak", (zip_reads(z) or {}).get("d/") == LEAK)

z = zip_build([{"name": b"a.md", "data": CLEAN, "after": deflate(LEAK)}, {"name": b"b.md", "data": CLEAN}])
hidden("zip-gap.zip", z)
check("zip-gap.zip: Python's zipfile reads it as clean", zip_reads(z) == {"a.md": CLEAN, "b.md": CLEAN})

w("zip-empty.zip", zip_py([]))
check("zip-empty.zip is the 22-byte end record alone", len(zip_py([])) == 22)
fake = b"PK\x05\x06" + b"\x00" * 16 + b"\xff\xff"  # its comment length does not reach the end
w("zip-empty-comment.zip", zip_build([], comment=b"note " + fake + b" end"))
check("zip-empty-comment.zip: Python's zipfile opens it", zip_reads(zip_build([], comment=b"note " + fake + b" end")) == {})
# A comment holding a second end record that is itself consistent (it ends at the end of the file).
tail = b"x"
inner = b"PK\x05\x06" + b"\x00" * 16 + struct.pack("<H", len(tail))
w("zip-two-ends.zip", zip_build([], comment=inner + tail))

for tag, members in (("clean", [("readme.md", CLEAN), ("b.md", CLEAN)]), ("leak", [("readme.md", CLEAN), ("notes.md", LEAK)])):
    for z64 in (False, True):
        data = zip_nonseek(members, z64)
        name = "zip-desc-signed-%s-%s.zip" % ("zip64" if z64 else "zip32", tag)
        (hidden if tag == "leak" else w)(name, data)
        check(name + " has signed data descriptors and opens", b"PK\x07\x08" in data and zip_reads(data) is not None)
    for d in (12, 20):
        ents = [{"name": n.encode(), "data": c, "desc": d} for n, c in members]
        data = zip_build(ents)
        name = "zip-desc-unsigned-%s-%s.zip" % ("zip64" if d == 20 else "zip32", tag)
        (hidden if tag == "leak" else w)(name, data)
        check(name + " has no descriptor signature and opens", b"PK\x07\x08" not in data and zip_reads(data) == dict(members))

z = zip_build([{"name": b"a.md", "data": CLEAN, "desc": 16, "after": deflate(LEAK)}, {"name": b"b.md", "data": CLEAN}])
hidden("zip-desc-hidden.zip", z)
check("zip-desc-hidden.zip: Python's zipfile reads it as clean", zip_reads(z) == {"a.md": CLEAN, "b.md": CLEAN})
z = zip_build([{"name": b"a.md", "data": CLEAN, "desc": 16, "desc_crc": 12345}])
w("zip-desc-mismatch.zip", z)
check("zip-desc-mismatch.zip: Python's zipfile reads it as clean", zip_reads(z) == {"a.md": CLEAN})

z = zip_py([("readme.md", CLEAN)], zipfile.ZIP_LZMA)
w("zip-lzma.zip", z)
check("zip-lzma.zip: Python's zipfile reads the lzma member", zip_reads(z) == {"readme.md": CLEAN})
w("zip-bzip2-clean.zip", zip_py([("readme.md", CLEAN)], zipfile.ZIP_BZIP2))
hidden("zip-bzip2-leak.zip", zip_py([("notes.md", LEAK)], zipfile.ZIP_BZIP2))
w("zip-stored-clean.zip", zip_build([{"name": b"readme.md", "data": CLEAN, "method": 0}]))
w("zip-deflate-clean.zip", zip_build([{"name": b"a.md", "data": CLEAN}, {"name": b"b/c.md", "data": CLEAN * 50}]))
hidden("zip-deflate-leak.zip", zip_build([{"name": b"a.md", "data": CLEAN}, {"name": b"b/c.md", "data": LEAK}]))
w("zip-encrypted.zip", zip_build([{"name": b"a.md", "data": CLEAN, "method": 0, "flags": 1}]))
w("zip-badcrc.zip", zip_build([{"name": b"a.md", "data": CLEAN, "crc": 1}]))

z = zip_build([{"name": b"notes.md", "data": LEAK}])
for depth in (2, 3, 4):
    z = zip_build([{"name": b"inner%d.zip" % (depth - 1), "data": z}])
    hidden("zip-nest%d.zip" % depth, z)

# A sniffed text inside an archive (its chunk is skipped by gitleaks, so it must be retried).
lines = sniff_text(b"ustar", 256, None).count(b"\n")
hidden("zip-sniffed-member.zip", zip_build([{"name": b"notes.md", "data": sniff_text(b"ustar", 256, lines + 3)}]))


# ------------------------------------------------------------------ (b) tar
def tarbytes(members, fmt=tarfile.USTAR_FORMAT, pax=None):
    b = io.BytesIO()
    with tarfile.open(fileobj=b, mode="w", format=fmt) as t:
        for n, d in members:
            ti = tarfile.TarInfo(n)
            ti.size, ti.mtime = len(d), 0
            if pax:
                ti.pax_headers = dict(pax)
            t.addfile(ti, io.BytesIO(d))
    return b.getvalue()


def fix_sum(buf, at):
    blk = buf[at:at + 512]
    blk[148:156] = b" " * 8
    buf[at + 148:at + 156] = b"%06o\x00 " % sum(blk)


def tar_reads(data):
    """[(name, size, content, sparse)] as Python's tarfile reads DATA; None when it cannot."""
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as t:
            out = []
            for m in t.getmembers():
                fh = t.extractfile(m) if m.isfile() else None
                out.append((m.name, m.size, fh.read() if fh else None, m.issparse()))
            return out
    except Exception:  # noqa: BLE001 - a sanity probe
        return None


GZLEAK = gz(LEAK)
TCLEAN = tarbytes([("a.txt", CLEAN)])
TLEAK = tarbytes([("notes.gz", GZLEAK)])

v7 = bytearray(TLEAK)
with tarfile.open(fileobj=io.BytesIO(TLEAK)) as t:
    for m in t.getmembers():
        v7[m.offset + 257:m.offset + 500] = b"\x00" * 243
        fix_sum(v7, m.offset)
v7 = bytes(v7)
hidden("tar-v7.tar", v7)
check("tar-v7.tar has no ustar magic and Python's tarfile reads it", b"ustar" not in v7 and (tar_reads(v7) or [[None]])[0][0] == "notes.gz")

hidden("tar-concat.tar", TCLEAN + TLEAK)
check("tar-concat.tar: Python's tarfile stops at the first end marker", [m[0] for m in tar_reads(TCLEAN + TLEAK) or []] == ["a.txt"])
hidden("tar-nul-start.tar", b"\x00" * 1024 + TLEAK)

w("tar-junk.tar", TCLEAN + b"junk text after the archive\n")
check("tar-junk.tar: Python's tarfile reads it as clean", [m[0] for m in tar_reads(TCLEAN + b"junk text after the archive\n") or []] == ["a.txt"])
# The leak, gzipped, inside the archive's own end padding (the file keeps its length).
pad_hidden = bytearray(TCLEAN)
pad_hidden[2048:2048 + len(GZLEAK)] = GZLEAK
pad_hidden = bytes(pad_hidden)
hidden("tar-pad-hidden.tar", pad_hidden)
check("tar-pad-hidden.tar: Python's tarfile reads it as clean", [m[0] for m in tar_reads(pad_hidden) or []] == ["a.txt"])
w("tar-nul-pad.tar", TCLEAN + b"\x00" * 700)
bare = TCLEAN[:1024]  # one header and one data block, no end marker
w("tar-bare-end.tar", bare)
check("tar-bare-end.tar: Python's tarfile reads its one member", [m[0] for m in tar_reads(bare) or []] == ["a.txt"])
w("tar-truncated.tar", tarbytes([("big.bin", RND.randbytes(5000))])[:1500])

longname = "d/" + "n" * 150
w("tar-gnu-long-clean.tar", tarbytes([(longname + ".txt", CLEAN)], tarfile.GNU_FORMAT))
hidden("tar-gnu-long-leak.tar", tarbytes([(longname + ".gz", GZLEAK)], tarfile.GNU_FORMAT))
check("tar-gnu-long: GNU long names are used", b"././@LongLink" in tarbytes([(longname, CLEAN)], tarfile.GNU_FORMAT))


def pax_override(d, name):
    """A pax member whose size comes from the pax header; the ustar size field says 0."""
    buf = bytearray(tarbytes([(name, d)], tarfile.PAX_FORMAT, pax={"size": str(len(d))}))
    with tarfile.open(fileobj=io.BytesIO(bytes(buf))) as t:
        m = t.getmembers()[0]
    hdr = m.offset_data - 512
    buf[hdr + 124:hdr + 136] = b"00000000000\x00"
    fix_sum(buf, hdr)
    return bytes(buf)


p = pax_override(CLEAN * 40, "notes.txt")
w("tar-pax-clean.tar", p)
check("tar-pax-clean.tar: the size comes from the pax header", (tar_reads(p) or [[0, 0, 0]])[0][2] == CLEAN * 40)
p = pax_override(GZLEAK, "notes.gz")
hidden("tar-pax-leak.tar", p)
check("tar-pax-leak.tar: the size comes from the pax header", (tar_reads(p) or [[0, 0, 0]])[0][2] == GZLEAK)

sp = bytearray(tarbytes([("s.bin", CLEAN)], tarfile.GNU_FORMAT))
sp[156:157] = b"S"
sp[386:398] = b"%011o\x00" % 0
sp[398:410] = b"%011o\x00" % len(CLEAN)
sp[482] = 0
sp[483:495] = b"%011o\x00" % (len(CLEAN) + 4096)
fix_sum(sp, 0)
sp = bytes(sp)
w("tar-sparse.tar", sp)
check("tar-sparse.tar: Python's tarfile reads a sparse member", bool(tar_reads(sp)) and tar_reads(sp)[0][3])

# ------------------------------------------------------------------ (b) gzip, bzip2, xz
XZ = lzma.compress
XLEAK = LEAK * 20  # small xz input is stored as plain bytes; repeated, it is really compressed
hidden("xz-two.xz", XZ(CLEAN) + XZ(XLEAK))
hidden("xz-pad-two.xz", XZ(CLEAN) + b"\x00" * 4 + XZ(XLEAK))
hidden("gz-pad-two.gz", gz(CLEAN) + b"\x00" * 512 + gz(LEAK))
hidden("gz-two.gz", gz(CLEAN) + gz(LEAK))
hidden("bz-two.bz2", bz2.compress(CLEAN) + bz2.compress(LEAK))
w("gz-pad-junk.gz", gz(CLEAN) + b"\x00" * 8 + b"junk after the stream\n")
w("xz-pad-junk.xz", XZ(CLEAN) + b"\x00" * 4 + b"junk after the stream\n")
w("bz-junk.bz2", bz2.compress(CLEAN) + b"junk after the stream\n")
hidden("gz-then-bz2.gz", gz(CLEAN) + bz2.compress(LEAK))
hidden("gz-then-xz.gz", gz(CLEAN) + XZ(XLEAK))
t = bz2.compress(LEAK + RND.randbytes(2048))
w("bz-cut.bz2", t[:len(t) // 2])
t = XZ(LEAK + RND.randbytes(2048))
w("xz-cut.xz", t[:len(t) // 2])
w("gz-pad.gz", gz(CLEAN) + b"\x00" * 512)


def bgzf_block(d):
    c = zlib.compressobj(6, zlib.DEFLATED, -15)
    raw = c.compress(d) + c.flush()
    bsize = 12 + 6 + len(raw) + 8 - 1
    return (b"\x1f\x8b\x08\x04\x00\x00\x00\x00\x00\xff\x06\x00BC\x02\x00" + struct.pack("<H", bsize)
            + raw + struct.pack("<II", zlib.crc32(d), len(d)))


BGZF_EOF = bytes.fromhex("1f8b08040000000000ff0600424302001b0003000000000000000000")
bg = b"".join(bgzf_block(b"chr1\t%d\t.\tA\tG\t50\tPASS\t.\n" % i) for i in range(3000)) + BGZF_EOF
w("bgzf-3000.vcf.gz", bg)
check("bgzf-3000.vcf.gz: gzip reads all 3000 blocks", gzip.decompress(bg).count(b"\n") == 3000)
w("gz-empty-140000.gz", gz(b"") * 140000)

# ------------------------------------------------------------------ (c) UTF-16 / UTF-32, no BOM
S = LEAK.decode()
w("utf16le-nobom.txt", S.encode("utf-16-le"))
w("utf16be-nobom.txt", S.encode("utf-16-be"))
w("utf16le-cjk.txt", ("界" * 7 + H.decode()).encode("utf-16-le"))
w("utf16be-cjk.txt", ("界" * 7 + H.decode()).encode("utf-16-be"))
w("utf32le-nobom.txt", S.encode("utf-32-le"))
w("utf32be-nobom.txt", S.encode("utf-32-be"))
w("utf16le-nobom-clean.txt", CLEAN.decode().encode("utf-16-le"))
w("utf32le-nobom-clean.txt", CLEAN.decode().encode("utf-32-le"))
w("dsstore-like.bin", b"\x00\x00\x00\x01Bud1\x00\x00\x10\x00\x00\x00\x08" + S.encode("utf-16-be") + b"\x00\x00\x00\x00Iloc")
for n in ("utf16le-nobom.txt", "utf16be-nobom.txt", "utf16le-cjk.txt", "utf32le-nobom.txt", "dsstore-like.bin"):
    check(n + " hides the leak from a raw read", H not in open(os.path.join(OUT, n), "rb").read())


# ------------------------------------------------------------------ (d) other binaries
def sevenz(packed):
    nexthdr = b"\x01\x04\x06\x00\x01\x09" + bytes([len(packed)]) + b"\x00\x07\x0b\x01\x00\x01\x23\x03\x01\x01\x05\x5d\x00\x00\x00\x00"
    start = struct.pack("<QQI", len(packed), len(nexthdr), zlib.crc32(nexthdr))
    return b"7z\xbc\xaf\x27\x1c\x00\x04" + struct.pack("<I", zlib.crc32(start)) + start + packed + nexthdr


def rar5(packed):
    return (b"Rar!\x1a\x07\x01\x00" + b"\x33\x92\xb5\xe5\x0a\x01\x05\x06\x00\x05\x01\x01\x80\x80\x00"
            + b"\x00\x00\x00\x00\x02\x03\x0b" + bytes([len(packed)]) + b"\x00\x04\x00\x20\x00\x00\x08notes.md"
            + packed + b"\x1d\x77\x56\x51\x03\x05\x04\x00")


def zstd_raw(text):
    assert len(text) < 256
    return b"\x28\xb5\x2f\xfd\x20" + bytes([len(text)]) + struct.pack("<I", (len(text) << 3) | 1)[:3] + text


for tag, data in (("clean", CLEAN), ("leak", LEAK)):
    w("sevenz-%s.7z" % tag, sevenz(data))
    w("rar-%s.rar" % tag, rar5(data))
    w("zstd-%s.zst" % tag, zstd_raw(data))
check("the 7z, rar and zstd fixtures hold a NUL and the leak as plain text",
      all(b"\0" in open(os.path.join(OUT, n), "rb").read() and H in open(os.path.join(OUT, n), "rb").read()
          for n in ("sevenz-leak.7z", "rar-leak.rar", "zstd-leak.zst")))
w("binary-leak.bin", b"\x00\x01\x02\x03" + LEAK + b"\x00\xfe\xff")
w("binary-clean.bin", b"\x00\x01\x02\x03" + CLEAN + b"\x00\xfe\xff" + RND.randbytes(64))
# More archives the guard cannot open, each by its leading signature, all with clean content.
w("lz4-clean.lz4", b"\x04\x22\x4d\x18\x60\x40\x82" + struct.pack("<I", len(CLEAN) | 0x80000000) + CLEAN
  + b"\x00\x00\x00\x00")
w("lzip-clean.lz", b"LZIP\x01\x0c" + RND.randbytes(40) + struct.pack("<IQQ", zlib.crc32(CLEAN), len(CLEAN), 66))
w("compress-clean.Z", b"\x1f\x9d\x90" + RND.randbytes(30))
w("cab-clean.cab", b"MSCF\x00\x00\x00\x00" + struct.pack("<IIIBBHHHHH", 80 + len(CLEAN), 0, 44, 3, 1, 1, 1, 0, 0, 0)
  + b"\x00" * 16 + b"readme.txt\x00" + CLEAN)
hidden("zip-holding-lz4.zip", zip_build([{"name": b"data/readme.lz4", "data": open(os.path.join(OUT, "lz4-clean.lz4"), "rb").read()}]))
hidden("tgz-holding-7z.tar.gz", gz(tarbytes([("backup.7z", sevenz(CLEAN))])))
# Text that only names a format: the letters without the rest of the signature.
w("text-lzip.txt", b"LZIP is a compressed format; this note only names it.\n")
w("text-mscf.txt", b"MSCF starts a cabinet file; this note only names it.\n")
t = gz(CLEAN * 50 + RND.randbytes(2048))
w("gz-cut-clean.gz", t[:len(t) // 2])
w("binary-highbytes-leak.bin", b"\x00\xe9\xe9\xe9" + LEAK.rstrip(b"\n") + b"\xe9\xe9\x00")
w("binary-quote.bin", b"\x89PNG\r\n\x1a\n\x00\x00\x00\n> quoted from a chat, inside an image\n\x00\x00IEND")
w("text-quote.txt", b"Intro.\n\n> quoted from a chat\n")

with open(os.path.join(OUT, "meta.txt"), "w") as f:
    f.write("\n".join(META) + "\n")
with open(os.path.join(OUT, "sanity.txt"), "w") as f:
    f.write("\n".join(SANITY) + "\n")
PY

meta() { awk -v k="$1" '$1 == k { print $2 }' "$FX/meta.txt"; }

echo "== sanity: the fixtures are what the cases say"
# RED WHEN: a fixture stops being what its case needs (Python's own reader no longer fooled, a
# leak no longer hidden from a raw read, a descriptor or a sparse member not written), so a case
# below would pass without proving anything.
while read -r verdict what; do
  [ -n "$verdict" ] || continue
  if [ "$verdict" = ok ]; then ok "sanity: $what"; else bad "sanity: $what" "fixture is not what the case needs"; fi
done <"$FX/sanity.txt"
# RED WHEN: gitleaks stops skipping the sniffed chunks, so every case in (a) would be vacuous.
mkdir -p "$WORK/sniff-probe/src"
for f in sniff-tar-leak.txt sniff-dicm-leak.txt sniff-iso-leak.txt; do
  { printf '\n'; cat "$FX/$f"; } >"$WORK/sniff-probe/src/$f"
done
(cd "$WORK/sniff-probe" && "$REAL_GITLEAKS" dir src --config "$RULES" --no-banner --report-format json \
  --report-path rep.json --exit-code 0 --log-level debug 2>log.txt)
n_skip="$(grep -c 'skipping binary file' "$WORK/sniff-probe/log.txt")"
n_found="$("$REAL_PY" -c 'import json,sys; print(len(json.load(open(sys.argv[1]))))' "$WORK/sniff-probe/rep.json" 2>/dev/null)"
if [ "$n_skip" = 3 ] && [ "$n_found" = 0 ]; then ok "sanity: gitleaks skips all three sniffed chunks silently"; else bad "sanity: gitleaks skips all three sniffed chunks silently" "skipped $n_skip, found '$n_found'"; fi

_bin() { _run python3 "$SCAN" text --label demo <"$1"; }
# fcase NAME FILE WANT [NEEDLE...]: text mode on a fixture. WANT 0 (clean, gitleaks ran), 1 (a
# home path found) or 2 (refused, with `could not check`).
fcase() {
  local name="$1" file="$2" want="$3"
  shift 3
  _bin "$FX/$file"
  case "$want" in
    0) expect_rc "$name" 0 @scanned "$@" ;;
    1) expect_rc "$name" 1 home-folder-path "$@" ;;
    2) expect_rc "$name" 2 "could not check" "$@" ;;
    *) die "fcase: bad want $want" ;;
  esac
}

# CI repository for committed fixtures.
FR="$WORK/fci"
git init -q "$FR"
commit_file "$FR" a.txt "start" "init"
FRBASE="$(git -C "$FR" rev-parse HEAD)"
_fci() { # REPO BASE HEAD [PR_BODY]
  (unset PRIVATE_NOTES_DIR && PR_TITLE="Add files" PR_BODY="${4:-Adds files.}" _run python3 "$SCAN" ci --repo "$1" --base "$2" --head "$3")
}
# fci NAME FILE PATH WANT [NEEDLE...]: commit fixture FILE at PATH on a fresh branch; CI mode.
fci() {
  local name="$1" file="$2" path="$3" want="$4"
  shift 4
  git -C "$FR" checkout -q -B "f-$RANDOM" "$FRBASE" || die "fci branch"
  mkdir -p "$(dirname "$FR/$path")"
  cp "$FX/$file" "$FR/$path"
  if ! { git -C "$FR" add -- "$path" && git -C "$FR" commit -q -m "add a file"; }; then die "fci commit $path"; fi
  _fci "$FR" "$FRBASE" "$(git -C "$FR" rev-parse HEAD)"
  case "$want" in
    0) expect_rc "$name" 0 @scanned "$@" ;;
    1) expect_rc "$name" 1 home-folder-path "$@" ;;
    2) expect_rc "$name" 2 "could not check" "$@" ;;
    *) die "fci: bad want $want" ;;
  esac
}
# expect_push_found NAME NEEDLE...: blocked by FINDINGS (not by an error), destination unchanged.
expect_push_found() {
  local name="$1"
  shift
  if grep -q -F "could not check" "$ERR"; then bad "$name" "blocked by an error, not by a finding$(_hint)"; return; fi
  expect_blocked "$name" "$@"
}

# ========================================================================= (a) sniffed chunks
echo "== (a) text that gitleaks sniffs as a binary is read, never skipped"
L_TAR="$(meta sniff-tar-line)"
L_DICM="$(meta sniff-dicm-line)"
L_ISO="$(meta sniff-iso-line)"
# RED WHEN: a chunk gitleaks skips (DEBUG log only) is not retried, so its leak passes as clean.
fcase "sniffed (text): 'ustar' at byte 256 with a home path -> found on its line" sniff-tar-leak.txt 1 "demo:$L_TAR"
fcase "sniffed (text): 'DICM' at byte 127 with a home path -> found on its line" sniff-dicm-leak.txt 1 "demo:$L_DICM"
fcase "sniffed (text): 'CD001' at byte 32768 with a home path -> found on its line" sniff-iso-leak.txt 1 "demo:$L_ISO"
# RED WHEN: a skipped chunk is blocked (exit 2) instead of retried, or its retry reports a
# finding that is not there (partners of the three above).
fcase "sniffed (text): clean text with 'ustar' at byte 256 passes" sniff-tar.txt 0
fcase "sniffed (text): clean text with 'DICM' at byte 127 passes" sniff-dicm.txt 0
fcase "sniffed (text): clean text with 'CD001' at byte 32768 passes" sniff-iso.txt 0
# RED WHEN: the retry only covers top-level files, not a file read out of an archive.
fcase "sniffed (text): a sniffed text inside a zip -> found" zip-sniffed-member.zip 1 "inside the archive"
# RED WHEN: CI does not retry a skipped file chunk, or maps its line wrongly.
fci "sniffed (ci): 'ustar' at byte 256 in a committed file -> found on its line" sniff-tar-leak.txt notes.md 1 "notes.md:$L_TAR"
fci "sniffed (ci): the clean partner passes" sniff-tar.txt notes.md 0
# RED WHEN: the retry only covers file content, not the PR body (every chunk can be sniffed).
_fci "$FR" "$FRBASE" "$FRBASE" "$(cat "$FX/sniff-message.txt")"
expect_rc "sniffed (ci): a PR body with 'ustar' at byte 256 -> found" 1 home-folder-path body
vis acme/f-sniff public
mkpush fsniff "$(gh_url acme/f-sniff)"
D="$P/fsniff"
cp "$FX/t9-notes.md" "$D/notes.md"
git -C "$D" add notes.md && git -C "$D" commit -q -m "tar notes"
gpush "$D" "$D.git" origin main
# RED WHEN: a push misses the key, address and home path in a file gitleaks skips.
expect_push_found "sniffed (push): a key, an address and a home path after 'ustar' at byte 256 are blocked" aws-access-token personal-email home-folder-path "notes.md:5"
vis acme/f-sniff2 public
mkpush fsniff2 "$(gh_url acme/f-sniff2)"
D="$P/fsniff2"
git -C "$D" commit -q --allow-empty --cleanup=verbatim -F "$FX/sniff-message.txt"
gpush "$D" "$D.git" origin main
# RED WHEN: a commit message chunk that gitleaks skips is not retried.
expect_push_found "sniffed (push): a commit message with 'ustar' at byte 256 and a home path is blocked" home-folder-path

echo "== (a) a gitleaks that drops a file or misbehaves blocks (the canary)"
# Wrappers stand in for gitleaks. Each runs the spy (so @scanned holds), and misbehaves on the
# files of the folder it is asked to read that hold the marker line `dropmarker-q7z`:
#   truncate  empties those files before every run (an open that failed silently)
#   filter    removes their findings from the JSON report after every run
#   wrn, err  add a WRN or ERR line to stderr; inf, dbg add an ordinary INF or DBG line
#   garbage   adds a line that is not a log line
#   skipother adds a `skipping` line naming a file that is not a chunk
#   skiponce  adds a `skipping` line for every file it reads, on its FIRST run only
#   skipall   adds a `skipping` line for every file it reads, on every run
WRAPPY="$WORK/wrap.py"
cat >"$WRAPPY" <<'EOF'
import json, os, subprocess, sys
real, mode, state = sys.argv[1:4]
args = sys.argv[4:]
mark = b"dropmarker-q7z"
# The folder gitleaks reads: the argument after `dir` (every file in it, whatever its name, so a
# retry folder is treated the same way).
target = args[args.index("dir") + 1] if "dir" in args[:-1] else None
chunks = []
if target and os.path.isdir(target):
    for root, _dirs, files in os.walk(target):
        chunks += [os.path.join(root, f) for f in files]
chunks = sorted(set(chunks))
marked = set()
for p in chunks:
    try:
        with open(p, "rb") as fh:
            if mark in fh.read():
                marked.add(os.path.realpath(p))
    except OSError:
        pass
if mode == "truncate":
    for p in marked:
        open(p, "wb").close()
first = not os.path.exists(state)
open(state, "a").close()
rc = subprocess.run([real] + args).returncode
if mode == "filter":
    rp = None
    for i, a in enumerate(args):
        if a == "--report-path" and i + 1 < len(args):
            rp = args[i + 1]
        elif a.startswith("--report-path="):
            rp = a.split("=", 1)[1]
    if rp and os.path.exists(rp):
        with open(rp) as fh:
            found = json.load(fh)
        keep = [f for f in found if os.path.realpath(str(f.get("File", ""))) not in marked]
        with open(rp, "w") as fh:
            json.dump(keep, fh)
t = "\x1b[90m2:30AM\x1b[0m "
def skip(path):
    return t + "DBG skipping binary file \x1b[36mmime_type=\x1b[0mapplication/x-tar \x1b[36mpath=\x1b[0m" + path + "\n"
extra = {
    "wrn": t + "\x1b[33mWRN\x1b[0m \x1b[1msomething was not read\x1b[0m\n",
    "err": t + "\x1b[31mERR\x1b[0m \x1b[1mfailed to read a file\x1b[0m\n",
    "inf": t + "\x1b[32mINF\x1b[0m \x1b[1man ordinary note\x1b[0m\n",
    "dbg": t + "DBG an ordinary debug note\n",
    "garbage": "this is not a log line\n",
    "skipother": skip("/tmp/elsewhere/notes.bin"),
}.get(mode, "")
if mode == "skipall" or (mode == "skiponce" and first):
    extra = "".join(skip(p) for p in chunks)
sys.stderr.write(extra)
sys.exit(rc)
EOF
for m in pass truncate filter wrn err inf dbg garbage skipother skiponce skipall; do
  mkdir -p "$WORK/wrap-$m"
  printf '#!/bin/sh\nexec %s %s %s %s %s "$@"\n' "'$REAL_PY'" "'$WRAPPY'" "'$SPYBIN/gitleaks'" "'$m'" "'$WORK/wrap-$m.state'" >"$WORK/wrap-$m/gitleaks"
  chmod +x "$WORK/wrap-$m/gitleaks"
done
# wcase NAME MODE FILE WANT [NEEDLE...]: text mode with the MODE wrapper first on PATH.
wcase() {
  local name="$1" mode="$2" file="$3" want="$4"
  shift 4
  rm -f "$WORK/wrap-$mode.state"
  PATH="$WORK/wrap-$mode:$PATH" _bin "$FX/$file"
  case "$want" in
    0) expect_rc "$name" 0 @scanned "$@" ;;
    1) expect_rc "$name" 1 home-folder-path "$@" ;;
    2) expect_rc "$name" 2 "could not check" "$@" ;;
  esac
}
# RED WHEN: the wrapper itself changes what is found (partners: every case below relies on it).
wcase "canary: a pass-through wrapper finds the leak" pass marked-leak.txt 1 "demo:2"
wcase "canary: a pass-through wrapper passes clean text" pass marked-clean.txt 0
# RED WHEN: a chunk gitleaks never really read (its file emptied under it) counts as clean.
wcase "canary: a gitleaks that silently reads an empty file -> exit 2" truncate marked-leak.txt 2
wcase "canary: ... even when the dropped text is clean -> exit 2" truncate marked-clean.txt 2
# RED WHEN: a chunk whose findings never come back (the canary among them) counts as clean.
wcase "canary: a gitleaks that reports nothing for one file -> exit 2" filter marked-leak.txt 2
# RED WHEN: the dropping wrappers block everything (partner: no marked chunk, normal result).
wcase "canary: the dropping wrapper leaves unmarked text alone" truncate leak.txt 1 "demo:1"
wcase "canary: the filtering wrapper leaves unmarked clean text alone" filter clean.txt 0
# RED WHEN: a WRN or ERR line from gitleaks no longer blocks.
wcase "log: a WRN line from gitleaks -> exit 2" wrn clean.txt 2
wcase "log: an ERR line from gitleaks -> exit 2" err clean.txt 2
# RED WHEN: a stray line that is not a log line is ignored.
wcase "log: a line that is not a log line -> exit 2" garbage clean.txt 2
# RED WHEN: a skip line that names a file outside this run's chunks is ignored.
wcase "log: a skip line naming a file that is not a chunk -> exit 2" skipother clean.txt 2
# RED WHEN: ordinary INF or DBG lines (gitleaks prints many at debug level) block a clean scan.
wcase "log: an ordinary INF line does not block" inf clean.txt 0
wcase "log: an ordinary DBG line does not block" dbg clean.txt 0
# RED WHEN: a chunk named by a skip line is not retried (or its retry is not read).
wcase "log: a chunk skipped once is retried and its leak found" skiponce leak.txt 1 "demo:1"
wcase "log: a chunk skipped once is retried and passes when clean" skiponce clean.txt 0
# RED WHEN: a chunk skipped again on the retry counts as read.
wcase "log: a chunk skipped on the retry too -> exit 2" skipall clean.txt 2

# ========================================================================= (b) zip
echo "== (b) zip: read completely or refused"
# RED WHEN: concatenated zips are read the way Python's zipfile reads them (only the last).
fcase "zip: two zips back to back, the leak in the first -> exit 2" zip-concat.zip 2
# RED WHEN: bytes after the end record are ignored.
fcase "zip: text after the end record -> exit 2" zip-trail.zip 2
# RED WHEN: data after the first deflate stream inside an entry's compressed extent is ignored.
fcase "zip: a second deflate stream hidden inside an entry -> exit 2" zip-second-stream.zip 2
# RED WHEN: directory entries are skipped without reading what they hold.
fcase "zip: a directory entry carrying a deflated home path -> found" zip-dir-data.zip 1
# RED WHEN: bytes between two entries (not listed in the directory) are ignored.
fcase "zip: a deflated home path in a gap between entries -> exit 2" zip-gap.zip 2
fcase "zip: hidden bytes after an entry's data descriptor -> exit 2" zip-desc-hidden.zip 2
# RED WHEN: a data descriptor that disagrees with the central directory is accepted.
fcase "zip: a data descriptor whose CRC disagrees with the directory -> exit 2" zip-desc-mismatch.zip 2
# RED WHEN: the completeness walk refuses ordinary zips (partners of the cases above).
fcase "zip: an empty zip passes" zip-empty.zip 0
fcase "zip: an empty zip whose comment holds an end-record signature passes" zip-empty-comment.zip 0
fcase "zip: a stored entry passes" zip-stored-clean.zip 0
fcase "zip: deflated entries in a folder pass" zip-deflate-clean.zip 0
fcase "zip: ... and a home path in one is found" zip-deflate-leak.zip 1
# RED WHEN: two end records that both end at the end of the file are resolved by a guess.
fcase "zip: a comment holding a second consistent end record -> exit 2" zip-two-ends.zip 2
# RED WHEN: data descriptors (signed or not, zip32 or zip64) are not matched to the directory.
for k in signed-zip32 signed-zip64 unsigned-zip32 unsigned-zip64; do
  fcase "zip: data descriptors ($k) pass when clean" "zip-desc-$k-clean.zip" 0
  fcase "zip: data descriptors ($k) with a home path -> found" "zip-desc-$k-leak.zip" 1
done
# RED WHEN: a method other than stored, deflate or bzip2 is decoded by a library that may read
# less than the entry holds (the contract allows only 0, 8 and 12).
fcase "zip: an lzma (method 14) entry -> exit 2" zip-lzma.zip 2
# RED WHEN: bzip2 entries are refused or not read (partner).
fcase "zip: a bzip2 entry passes when clean" zip-bzip2-clean.zip 0
fcase "zip: a bzip2 entry with a home path -> found" zip-bzip2-leak.zip 1
# RED WHEN: an encrypted entry or a CRC mismatch is passed.
fcase "zip: an encrypted entry -> exit 2" zip-encrypted.zip 2
fcase "zip: an entry whose CRC does not match -> exit 2" zip-badcrc.zip 2
# RED WHEN: the nesting limit moves (four deep refused, three deep read).
fcase "zip: nested four deep -> exit 2" zip-nest4.zip 2
fcase "zip: nested three deep -> found" zip-nest3.zip 1
fci "zip (ci): two zips back to back -> exit 2" zip-concat.zip pkg/bundle.zip 2
fci "zip (ci): a directory entry carrying a home path -> found" zip-dir-data.zip pkg/bundle.zip 1

# ========================================================================= (b) tar
echo "== (b) tar: found by its checksum, read completely or refused"
# RED WHEN: a tar is recognised by 'ustar' at byte 257 (a V7 tar has none).
fcase "tar: a V7 tar (no ustar magic) holding a gzipped home path -> found" tar-v7.tar 1
# RED WHEN: text with 'ustar' at byte 257 is read as a broken tar (exit 2) instead of as text.
# (Contract changed: a tar is now found by its header checksum, not by 'ustar'; this was exit 2.)
fcase "tar: text with 'ustar' at byte 257 and a home path -> found" ustar257-leak.txt 1
fcase "tar: clean text with 'ustar' at byte 257 passes" ustar257-clean.txt 0
# RED WHEN: reading stops at the first end-of-archive marker.
fcase "tar: two tars back to back, the leak in the second -> found" tar-concat.tar 1
# RED WHEN: leading NUL blocks hide the tar after them.
fcase "tar: 1024 NUL bytes, then a tar holding a gzipped home path -> found" tar-nul-start.tar 1
# RED WHEN: bytes after the archive (or inside its end padding) are ignored.
fcase "tar: text after the archive -> exit 2" tar-junk.tar 2
fcase "tar: a gzipped home path inside the end padding -> exit 2" tar-pad-hidden.tar 2
# RED WHEN: ordinary tar endings are refused (partners).
fcase "tar: extra NUL padding (a partial block) passes" tar-nul-pad.tar 0
fcase "tar: a tar with no end marker passes" tar-bare-end.tar 0
# RED WHEN: a member that runs past the end of the file is read as far as it goes.
fcase "tar: a truncated member -> exit 2" tar-truncated.tar 2
# RED WHEN: GNU long names or pax size records are not resolved (the walk would misalign).
fcase "tar: a GNU long-name member passes when clean" tar-gnu-long-clean.tar 0
fcase "tar: a GNU long-name member holding a gzipped home path -> found" tar-gnu-long-leak.tar 1
fcase "tar: a pax member whose size comes from the pax header passes when clean" tar-pax-clean.tar 0
fcase "tar: ... and holding a gzipped home path -> found" tar-pax-leak.tar 1
# RED WHEN: a sparse member (holes the guard does not rebuild) is read as if complete.
fcase "tar: a sparse member -> exit 2" tar-sparse.tar 2
fci "tar (ci): two tars back to back, the leak in the second -> found" tar-concat.tar pkg/x.tar 1
fci "tar (ci): text with 'ustar' at byte 257 and a home path -> found" ustar257-leak.txt notes.txt 1

# ========================================================================= (b) streams
echo "== (b) gzip, bzip2, xz: every stream, nothing left over"
# RED WHEN: only the first stream is read.
fcase "streams: two xz streams, the leak in the second -> found" xz-two.xz 1
fcase "streams: two gzip streams, the leak in the second -> found" gz-two.gz 1
fcase "streams: two bzip2 streams, the leak in the second -> found" bz-two.bz2 1
# RED WHEN: NUL padding between streams ends the reading.
fcase "streams: xz streams with 4 NUL bytes between, the leak in the second -> found" xz-pad-two.xz 1
fcase "streams: gzip streams with 512 NUL bytes between, the leak in the second -> found" gz-pad-two.gz 1
# RED WHEN: bytes after the last stream (after NUL padding or not) are read as a loose file.
fcase "streams: NUL padding then junk after a gzip stream -> exit 2" gz-pad-junk.gz 2
fcase "streams: NUL padding then junk after an xz stream -> exit 2" xz-pad-junk.xz 2
fcase "streams: junk after a bzip2 stream -> exit 2" bz-junk.bz2 2
# RED WHEN: a stream of another format after the first is accepted.
fcase "streams: a gzip stream then a bzip2 stream -> exit 2" gz-then-bz2.gz 2
fcase "streams: a gzip stream then an xz stream -> exit 2" gz-then-xz.gz 2
# RED WHEN: a truncated stream is read as far as it goes.
fcase "streams: a bzip2 file cut in half -> exit 2" bz-cut.bz2 2
fcase "streams: an xz file cut in half -> exit 2" xz-cut.xz 2
# RED WHEN: a stream count limit comes back (BGZF files hold thousands of streams).
fcase "streams: a clean BGZF-style file of 3000 gzip blocks passes" bgzf-3000.vcf.gz 0
fcase "streams: a clean gzip followed by NUL padding passes" gz-pad.gz 0
# RED WHEN: empty streams cost nothing, so a file of them is unbounded work.
fcase "streams: 140000 empty gzip streams exceed the unpack budget -> exit 2" gz-empty-140000.gz 2
fci "streams (ci): xz streams with NUL padding, the leak in the second -> found" xz-pad-two.xz data/x.xz 1
fci "streams (ci): a clean BGZF-style file passes" bgzf-3000.vcf.gz data/calls.vcf.gz 0

# ========================================================================= (c) encodings
echo "== (c) UTF-16 and UTF-32 without a byte-order mark"
# RED WHEN: UTF-16 or UTF-32 text without a byte-order mark is read only as bytes.
fcase "encoding: UTF-16LE without a mark -> found" utf16le-nobom.txt 1
fcase "encoding: UTF-16BE without a mark -> found" utf16be-nobom.txt 1
# RED WHEN: the UTF-16 view needs most of the text to be ASCII (a threshold), so CJK text first hides it.
fcase "encoding: UTF-16LE, seven CJK characters then a home path -> found" utf16le-cjk.txt 1
fcase "encoding: UTF-16BE, seven CJK characters then a home path -> found" utf16be-cjk.txt 1
fcase "encoding: UTF-32LE without a mark -> found" utf32le-nobom.txt 1
fcase "encoding: UTF-32BE without a mark -> found" utf32be-nobom.txt 1
# RED WHEN: a UTF-16 string inside other binary data (a .DS_Store-like file) is not read.
fcase "encoding: a UTF-16BE string inside a binary -> found" dsstore-like.bin 1
# RED WHEN: the extra views report something in clean text (partners).
fcase "encoding: clean UTF-16LE without a mark passes" utf16le-nobom-clean.txt 0
fcase "encoding: clean UTF-32LE without a mark passes" utf32le-nobom-clean.txt 0
fci "encoding (ci): UTF-16LE without a mark -> found" utf16le-nobom.txt notes16.txt 1

# ========================================================================= (d) other binaries
echo "== (d) archives the guard cannot open block; other binaries: printable text checked"
# RED WHEN: a 7z, rar or zstd file passes because its content looks clean (the guard cannot
# open it, so clean-looking text proves nothing about what is packed inside).
fcase "cannot open: a clean 7z file -> exit 2" sevenz-clean.7z 2
fcase "cannot open: a clean rar file -> exit 2" rar-clean.rar 2
fcase "cannot open: a clean zstd file -> exit 2" zstd-clean.zst 2
# RED WHEN: a 7z, rar or zstd file is read as an other binary (its plain text checked) instead of blocked.
fcase "cannot open: a 7z file with a stored home path -> exit 2" sevenz-leak.7z 2
fcase "cannot open: a rar file with a stored home path -> exit 2" rar-leak.rar 2
fcase "cannot open: a zstd file with a raw block holding a home path -> exit 2" zstd-leak.zst 2
# RED WHEN: lz4 frame, lzip, Unix compress or cabinet files pass (their signature is not checked).
fcase "cannot open: a clean lz4 frame -> exit 2" lz4-clean.lz4 2
fcase "cannot open: a clean lzip file -> exit 2" lzip-clean.lz 2
fcase "cannot open: a clean Unix compress (.Z) file -> exit 2" compress-clean.Z 2
fcase "cannot open: a clean Microsoft cabinet -> exit 2" cab-clean.cab 2
# RED WHEN: the signatures are checked only on the top-level file, not on files inside an archive.
fcase "cannot open: an lz4 frame inside a zip -> exit 2" zip-holding-lz4.zip 2
fcase "cannot open: a 7z file inside a tar.gz -> exit 2" tgz-holding-7z.tar.gz 2
# RED WHEN: the signature check matches too little (any binary, or the letters alone in text).
fcase "cannot open (partner): a clean binary with no such signature passes" binary-clean.bin 0
fcase "cannot open (partner): text starting with the letters LZIP passes" text-lzip.txt 0
fcase "cannot open (partner): text starting with the letters MSCF passes" text-mscf.txt 0
# RED WHEN: printable runs of a binary are not checked, or bytes 0x80-0xff hide a run next to them.
fcase "other binary: a home path between NUL bytes -> found" binary-leak.bin 1
fcase "other binary: a home path between high bytes and NULs -> found" binary-highbytes-leak.bin 1
_bin "$FX/binary-quote.bin"
# RED WHEN: reported-speech warnings are raised from a binary's printable runs.
if [ "$(rc)" = 0 ] && ! grep -q -F "may quote" "$ERR"; then ok "other binary: a quote line inside a binary prints no warning"; else bad "other binary: a quote line inside a binary prints no warning" "exit $(rc)$(_hint)"; fi
_bin "$FX/text-quote.txt"
# RED WHEN: the warning is dropped for text too (partner of the case above).
expect_rc "other binary: the same quote line in text still warns" 0 "may quote" "demo:3"
# RED WHEN: CI lets through a committed archive the guard cannot open.
fci "cannot open (ci): a clean zstd file -> exit 2" zstd-clean.zst data/x.zst 2
fci "cannot open (ci): a 7z file with a stored home path -> exit 2" sevenz-leak.7z data/x.7z 2
fci "cannot open (ci): a clean cabinet -> exit 2" cab-clean.cab data/x.cab 2
vis acme/f-arcmsg public
mkpush farcmsg "$(gh_url acme/f-arcmsg)"
D="$P/farcmsg"
cp "$FX/sevenz-clean.7z" "$D/backup.7z"
git -C "$D" add backup.7z && git -C "$D" commit -q -m "add a backup"
gpush "$D" "$D.git" origin main
# RED WHEN: the push block for an archive the guard cannot open does not name the file or does
# not say what to do (commit it unpacked; repack as zip, tar.gz or tar.xz; or keep it private).
expect_blocked "cannot open (push): a 7z file is blocked, naming it and what to do" "could not check" backup.7z \
  unpacked "zip, tar.gz or tar.xz" "private repository"
git -C "$D" reset -q --hard HEAD~1
cp "$FX/gz-cut-clean.gz" "$D/notes.txt.gz"
git -C "$D" add notes.txt.gz && git -C "$D" commit -q -m "add notes"
gpush "$D" "$D.git" origin main
# RED WHEN: the block for an archive that cannot be read completely does not name the file or
# does not say what to do.
expect_blocked "cannot open (push): a truncated gzip is blocked, naming it and what to do" "could not check" notes.txt.gz \
  unpacked "zip, tar.gz or tar.xz" "private repository"
vis acme/f-img public
mkpush fimg "$(gh_url acme/f-img)"
D="$P/fimg"
"$REAL_PY" -c '
import random, sys
r = random.Random(7)
sys.stdout.buffer.write(b"\xff\xd8\xff\xe0\x00\x10JFIF\x00" + r.randbytes(30_000_000) + b"\xff\xd9")' >"$D/photo.jpg"
git -C "$D" add photo.jpg && git -C "$D" commit -q -m "add a photo"
gpush "$D" "$D.git" origin main
# RED WHEN: bytes 0x80-0xff count as text again, or the minimum run drops below 12 characters,
# so random image data blocks as an address.
expect_pushed "other binary (push): 30 MB of random binary data after an image header passes" scanned

# ========================================================================= (e) gitlinks
echo "== (e) embedded repositories (gitlinks): the path is checked, the target is not read"
GL_A="$(printf '%s' 1234567890abcdef1234567890abcdef12345678)"
GL_B="$(printf '%s' 0fedcba9876543210fedcba9876543210fedcba9)"
vis acme/f-gl public
mkpush fgl "$(gh_url acme/f-gl)"
D="$P/fgl"
# RED WHEN: the setup stops leaving the target commit absent locally (the case would not test it).
if ! git -C "$D" cat-file -e "$GL_A" 2>/dev/null; then ok "sanity: the gitlink target is absent locally"; else bad "sanity: the gitlink target is absent locally" "it exists"; fi
git -C "$D" update-index --add --cacheinfo "160000,$GL_A,deps/libfoo"
git -C "$D" commit -q -m "add an embedded repository"
gpush "$D" "$D.git" origin main
# RED WHEN: a gitlink whose target is absent locally makes the scan fail (it must not be read).
expect_pushed "gitlink (push): a clean gitlink path passes though its target is absent" scanned
git -C "$D" update-index --add --cacheinfo "160000,$GL_A,deps${U}ers/jane/lib"
git -C "$D" commit -q -m "add another embedded repository"
gpush "$D" "$D.git" origin main
# RED WHEN: a gitlink's path is dropped before the names are checked.
expect_push_found "gitlink (push): a gitlink whose path holds a home path is blocked" home-folder-path
nohook_push "$D" origin main
git -C "$D" update-index --cacheinfo "160000,$GL_B,deps${U}ers/jane/lib"
git -C "$D" commit -q -m "move the embedded repository"
gpush "$D" "$D.git" origin main
# RED WHEN: a gitlink a new commit CHANGES (a new target) does not have its path checked.
expect_push_found "gitlink (push): changing a gitlink's target checks its path again" home-folder-path
git -C "$FR" checkout -q -B f-gitlink "$FRBASE" || die "branch"
git -C "$FR" update-index --add --cacheinfo "160000,$GL_A,vendor${U}ers/jane/lib"
git -C "$FR" commit -q -m "add an embedded repository"
_fci "$FR" "$FRBASE" "$(git -C "$FR" rev-parse HEAD)"
# RED WHEN: CI drops a gitlink's path, or fails on its absent target (exit 2 instead of 1).
expect_rc "gitlink (ci): a gitlink whose path holds a home path -> found" 1 home-folder-path "file name"

# ========================================================================= (f) one diff-tree
echo "== (f) one diff-tree for all new commits: same files, same names"
# mkrange DIR LEAK: base, then: a file named ':lead.txt'; an empty commit; a file named after
# the first new commit's sha; a merge with no combined changes; a merge whose resolution differs
# from both parents. LEAK (yes|no) puts a home path in each of the three new contents.
mkrange() {
  local r="$1" body="All tests pass." c1
  [ "$2" = yes ] && body="see $HOMEP"
  rg() { git -C "$r" "$@" >/dev/null || die "range: git $*"; }
  git init -q "$r" || die "init $r"
  printf 'a=1\n' >"$r/conf.txt"
  rg add -A
  rg commit -q -m base
  printf '%s\n' "$body" >"$r/:lead.txt"
  rg add -A
  rg commit -q -m "a file whose name starts with a colon"
  rg commit -q --allow-empty -m "an empty commit"
  c1="$(git -C "$r" rev-parse HEAD~1)"
  printf '%s\n' "$body" >"$r/$c1"
  rg add -A
  rg commit -q -m "a file named like a commit"
  rg checkout -q -b side
  printf 'side\n' >"$r/side.txt"
  rg add -A
  rg commit -q -m side
  rg checkout -q main
  printf 'main\n' >"$r/main.txt"
  rg add -A
  rg commit -q -m main
  rg merge -q --no-ff -m "a plain merge" side
  rg checkout -q -b other HEAD~1
  printf 'a=2\n' >"$r/conf.txt"
  rg commit -q -am other
  rg checkout -q main
  printf 'a=3\n' >"$r/conf.txt"
  rg commit -q -am mine
  git -C "$r" merge -q other >/dev/null 2>&1 # conflicts on purpose; resolved below
  printf 'a=4\n%s\n' "$body" >"$r/conf.txt"
  rg add -A
  rg commit -q -m "a merge resolution"
  printf '%s\n' "$c1" >"$r.c1"
}
mkrange "$WORK/range-clean" no
_fci "$WORK/range-clean" "$(git -C "$WORK/range-clean" rev-list --max-parents=0 HEAD)" "$(git -C "$WORK/range-clean" rev-parse HEAD)"
# RED WHEN: a path starting with ':' or named like a commit sha, an empty commit or a merge with
# no combined changes is misread by the one diff-tree parser (exit 2 on a clean range).
expect_rc "diff-tree: a clean range with odd paths, empty commits and merges passes" 0 @scanned
mkrange "$WORK/range-dirty" yes
C1="$(cat "$WORK/range-dirty.c1")"
_fci "$WORK/range-dirty" "$(git -C "$WORK/range-dirty" rev-list --max-parents=0 HEAD)" "$(git -C "$WORK/range-dirty" rev-parse HEAD)"
# RED WHEN: the batched parser drops a file or names it wrongly (each of the three must be found
# at its own path and line, and nothing else).
# A ':' is outside the names a report may print, so this place is withheld (it is still found).
expect_rc "diff-tree: the ':' path is found (its name withheld)" 1 "home-folder-path at a file whose name is withheld"
expect_rc "diff-tree: the path named like a commit sha is found under its name" 1 "home-folder-path at $C1:1"
expect_rc "diff-tree: the merge resolution is found under its name" 1 "home-folder-path at conf.txt:2"
n_items="$(grep -c '^  - ' "$ERR")"
if [ "$n_items" = 3 ]; then ok "diff-tree: exactly three findings in the range"; else bad "diff-tree: exactly three findings in the range" "got $n_items$(_hint)"; fi

echo "== (g) long lines: every byte is read with enough context around it"
# gitleaks reads a file in pieces of 100 000 bytes, each extended by at most 25 000 bytes to the
# next whitespace, so a token that crosses byte 125 000 of a line with no break was cut in two
# and missed. The scanner gives gitleaks overlapping windows small enough to be read whole.
# _long BEFORE TOKEN AFTER: BEFORE filler bytes, TOKEN, a space, AFTER filler bytes, no newline
# (TOKEN may be empty), scanned in text mode.
_long() {
  "$REAL_PY" -c 'import sys; sys.stdout.write("a" * int(sys.argv[1]) + sys.argv[2] + " " + "a" * int(sys.argv[3]))' \
    "$1" "$2" "$3" >"$WORK/long.txt"
  _run python3 "$SCAN" text --label demo <"$WORK/long.txt"
}
# RED WHEN: chunks are handed to gitleaks whole (no windows), or the windows are larger than
# gitleaks reads at once, so the token across byte 125 000 is cut in two and missed.
_long 124970 "$GHPAT" 150000
expect_rc "long line: a token across byte 125 000 of one line is found" 1 "github-pat at demo:1" @scanned
# RED WHEN: a window boundary turns clean filler into a finding or an error (partner of the case
# above: same shape, no token).
_long 124970 "" 150000
expect_rc "long line: the same line without a token is clean" 0 @scanned
# RED WHEN: windows do not overlap (or overlap by less than a token), so a token across the end
# of the first window (byte 90 000 of the text) is cut in two.
_long 89980 "$GHPAT" 150000
expect_rc "long line: a token across the first window's end is found" 1 "github-pat at demo:1" @scanned
# RED WHEN: a window past the first counts lines from its own start, not from the text's.
"$REAL_PY" -c '
import sys
lines = ["x" * 60] * 3000
lines[2499] = "key " + sys.argv[1]
sys.stdout.write("\n".join(lines) + "\n")' "$GHPAT" >"$WORK/many-lines.txt"
_run python3 "$SCAN" text --label demo <"$WORK/many-lines.txt"
expect_rc "long text: a finding past the first window keeps its line number" 1 "github-pat at demo:2500" @scanned

# The fixtures below come from one generator, so this file holds no key envelope and no term in
# a form a rule matches. The key bodies are base64 of a fixed phrase: not real keys.
LONGGEN="$WORK/longgen.py"
cat >"$LONGGEN" <<'EOF'
import base64, sys
kind, out = sys.argv[1], sys.argv[2]
args = sys.argv[3:]
dash = b"-" * 5
def pem(phrases, wrap):
    body = base64.b64encode(b"not-a-real-private-key" * phrases)
    if wrap:
        body = b"\n".join(body[i:i + 64] for i in range(0, len(body), 64))
    return dash + b"BEGIN PRIVATE KEY" + dash + b"\n" + body + b"\n" + dash + b"END PRIVATE KEY" + dash
def pgp():
    body = base64.encodebytes(b"not-a-real-pgp-private-key-block" * 470)
    return (dash + b"BEGIN PGP PRIVATE KEY BLOCK" + dash + b"\n\n" + body
            + dash + b"END PGP PRIVATE KEY BLOCK" + dash)
if kind == "pem":  # pem AT PHRASES WRAP: '!' filler, a newline, the key from byte AT, a newline, '!'
    at, phrases, wrap = int(args[0]), int(args[1]), args[2] == "wrap"
    data = b"!" * (at - 1) + b"\n" + pem(phrases, wrap) + b"\n" + b"!" * 100000
elif kind == "pgp":  # pgp AT: the PGP block on its own line from byte AT
    at = int(args[0])
    data = b"!" * (at - 1) + b"\n" + pgp() + b"\n" + b"!" * 100000
elif kind == "nokey-end":  # a key header with no end marker in a long line: no key, so clean
    data = b"!" * 73998 + b"\n" + dash + b"BEGIN PRIVATE KEY" + dash + b"A" * 150000
elif kind == "letters":  # letters AT TEXT: 'a' filler, TEXT from byte AT, 150 000 'a' (no break)
    at, text = int(args[0]), args[1].encode()
    data = b"a" * at + text + b"a" * 150000
elif kind == "word":  # word AT TEXT: '!' filler, TEXT from byte AT, 150 000 '!' (no newline)
    at, text = int(args[0]), args[1].encode()
    data = b"!" * at + text + b"!" * 150000
elif kind == "short-lines":  # 60-byte lines, no blank line, TOKEN from byte AT
    at, tok = int(args[0]), args[1].encode()
    line = b"y" * 59 + b"\n"
    data = (line * (at // 60 + 1))[:at] + b" " + tok + b" \n" + line * 3000
elif kind == "curl":  # a blank line every 3 lines; a curl command with a blank line, from byte AT
    at = int(args[0])
    para = (b"y" * 59 + b"\n") * 3 + b"\n"
    auth = base64.b64encode(b"someone:not-a-real-password").decode()
    cmd = ("curl https://api.example.org/v1 \\\n\n  -H \"Author" "ization: Basic %s\"\n" % auth).encode()
    pre = (para * (at // len(para) + 1))[:at]
    pre = pre[:pre.rfind(b"\n") + 1]
    data = pre + b"y" * (at - len(pre) - 1) + b"\n" + cmd + para * 3000
elif kind == "nested":  # N key headers, one end marker, padding: the key blocks nest
    n = int(args[0])
    data = (dash + b"BEGIN PRIVATE KEY" + dash + b"\n") * n + b"A" * 100 + b"\n" + dash + b"END PRIVATE KEY" + dash
    data += b"\n" + (b"y" * 59 + b"\n") * 2000
elif kind == "glued":  # a blank line every 3 lines; TOKEN glued to letters, from byte AT
    at, tok = int(args[0]), args[1].encode()
    para = (b"y" * 59 + b"\n") * 3 + b"\n"
    pre = (para * (at // len(para) + 1))[:at - 30]
    data = pre + b"\n" + b"a" * 29 + tok + b"a" * 20 + b"\n" + para * 2000
else:
    sys.exit("unknown fixture " + kind)
open(out, "wb").write(data)
if kind == "pem":
    print(len(pem(int(args[1]), args[2] == "wrap")))
elif kind == "pgp":
    print(len(pgp()))
EOF
_gen() { "$REAL_PY" -I "$LONGGEN" "$@" || die "longgen $1"; }
_text() { _run python3 "$SCAN" text --label demo <"$1"; }

echo "== (h) a private-key block longer than the window overlap is still found"
# A PEM key has no upper length in the secret rule, so no fixed overlap covers every key. A key
# block in text that gitleaks would split is read as a piece of its own.
size="$(_gen pem "$WORK/pem.txt" 2 600 one)"
[ "$size" -gt 16000 ] || die "the PEM fixture is only $size bytes"
_text "$WORK/pem.txt"
# RED WHEN: a long key near the start of a long line is missed (control for the cases below).
expect_rc "long key ($size bytes) near the start of a long line is found" 1 "private-key at demo:2" @scanned
for at in 73999 74000 89000 147999; do
  _gen pem "$WORK/pem.txt" "$at" 600 one >/dev/null
  _text "$WORK/pem.txt"
  # RED WHEN: a key block longer than the overlap that starts just before a window start is cut
  # between two windows and missed.
  expect_rc "long key ($size bytes, one line) from byte $at is found" 1 "private-key at demo:2" @scanned
  _gen pem "$WORK/pem.txt" "$at" 600 wrap >/dev/null
  _text "$WORK/pem.txt"
  # RED WHEN: as above, for the same key wrapped at 64 characters.
  expect_rc "long key (wrapped) from byte $at is found" 1 "private-key at demo:2" @scanned
done
# A key line that starts 4 000 bytes before the second window's start (beyond the 2 000 bytes an
# edge may move back) and runs past the first window's end: no window holds all of it.
for wrap in one wrap; do
  ksize="$(_gen pem "$WORK/pem.txt" 70000 900 "$wrap")"
  _text "$WORK/pem.txt"
  # RED WHEN: key blocks are not read as pieces of their own, so a key longer than the overlap
  # that no window edge can reach is cut between two windows and missed.
  expect_rc "long key ($ksize bytes, $wrap) from byte 70000 is found" 1 "private-key at demo:2" @scanned
done
psize="$(_gen pgp "$WORK/pgp.txt" 73999)"
_text "$WORK/pgp.txt"
# RED WHEN: a PGP private key block (a blank line after its header) longer than the overlap is cut.
expect_rc "PGP key block ($psize bytes) from byte 73999 is found" 1 "private-key at demo:2" @scanned
_gen pem "$WORK/pem.txt" 1000 6000 one >/dev/null
_text "$WORK/pem.txt"
# RED WHEN: a key block too long to be read in one piece passes instead of blocking.
expect_rc "a key block too long for one piece blocks" 2 "could not check" \
  "a private key block (or text shaped like one) crosses a scan window"
# T7. RED WHEN: the too-long error is raised without the rendered place (here the label demo)
# and its own fix line, or reuses the unreadable-file advice (repack as zip).
expect_rc "T7: the too-long key block message names the place and says to remove the key" 2 \
  "so demo could not be checked" "a private key never belongs in a public repository"
if grep -q -F "repack it" "$ERR"; then bad "T7: the too-long key block message is not the unreadable-file advice" "repack advice printed"; else
  ok "T7: the too-long key block message is not the unreadable-file advice"; fi
# RED WHEN: the block message quotes the key (the message is fixed).
if grep -q -F -e "bm90LWEtcmVhbC" "$ERR"; then bad "the key block message quotes no key text" "key text in stderr"; else
  ok "the key block message quotes no key text"; fi
_gen nokey-end "$WORK/nokey.txt"
_text "$WORK/nokey.txt"
# RED WHEN: a key header with no end marker blocks or is found (partner: no key, nothing to find).
expect_rc "a key header with no end marker in a long line is clean" 0 @scanned

echo "== (i) words at window edges are judged with the text around them"
# The private term (PTERM) must not match inside a longer word of letters and digits. Window
# edges must not invent a word boundary there.
for at in 73990 73999 74000 $((90000 - ${#PTERM})) 89990 89999; do
  _gen word "$WORK/word.txt" "$at" "x$PTERM"
  _text "$WORK/word.txt"
  # RED WHEN: private terms are matched in each window, so a window starting inside "x<term>"
  # loses the x and reports the term.
  expect_rc "x<term> from byte $at is clean" 0 @scanned
  _gen word "$WORK/word.txt" "$at" "${PTERM}x"
  _text "$WORK/word.txt"
  # RED WHEN: a window ending inside "<term>x" loses the x and reports the term.
  expect_rc "<term>x from byte $at is clean" 0 @scanned
  _gen word "$WORK/word.txt" "$at" "$PTERM"
  _text "$WORK/word.txt"
  # RED WHEN: the term itself is no longer found at a window edge (partner of the two above).
  expect_rc "the term alone from byte $at is found" 1 "private-term at demo:1" @scanned
done

# Inside a run of letters with no break, a window start cannot move to a real boundary. The term
# (written without its separator, which it also matches) ends at a break but starts inside a
# longer word, so it must not be found.
_gen letters "$WORK/word.txt" 74000 "${TERM_A}labs!"
_text "$WORK/word.txt"
# RED WHEN: private terms are matched on each window, so the window starting at byte 74 000,
# inside the run of letters, invents the word boundary the term needs before it.
expect_rc "the term after a long run of letters, at a window start, is clean" 0 @scanned
_gen word "$WORK/word.txt" 74000 "${TERM_A}labs!"
_text "$WORK/word.txt"
# RED WHEN: the separator-less form is not matched at all (partner: after a break it is found).
expect_rc "the same term after a break is found" 1 "private-term at demo:1" @scanned

echo "== (j) a text longer than one gitleaks piece is read as windows with real edges"
_gen short-lines "$WORK/short.txt" 124990 "$GHPAT"
_text "$WORK/short.txt"
# RED WHEN: only over-long lines are split: gitleaks cuts text of short lines with no blank line
# at byte 125 000 too (measured, 8.30.1), so the token across it is missed.
expect_rc "a token across byte 125 000 of short lines with no blank line is found" 1 "github-pat at demo:" @scanned
# An agent id shape: its rule needs a word boundary before it, and nothing after it.
AGENTID="too""lu_$(printf 'Ab3%.0s' 1 2 3 4 5 6 7 8)"
_gen glued "$WORK/glued.txt" 74000 "$AGENTID"
_text "$WORK/glued.txt"
# RED WHEN: a window edge is not moved back to a line start, so a window starting at byte 74 000
# invents the word boundary the rule needs before an agent id glued to letters.
expect_rc "an agent id glued to letters at byte 74 000 of text with blank lines is clean" 0 @scanned
_gen glued "$WORK/glued.txt" 74000 " $AGENTID"
_text "$WORK/glued.txt"
# RED WHEN: the agent id after a space is no longer found (partner: the case above is clean
# because of the glued letters, not because nothing is read there).
expect_rc "the same agent id after a space is found" 1 "agent-" @scanned
for at in 99970 99990 199970; do
  _gen curl "$WORK/curl.txt" "$at"
  _text "$WORK/curl.txt"
  # RED WHEN: text with blank lines is handed to gitleaks whole: gitleaks cuts it at a blank line
  # near byte 100 000 (measured, 8.30.1), so a curl command whose blank line is there is missed.
  expect_rc "a curl credential split by a blank line at byte $at is found" 1 "curl-auth-header at demo:" @scanned
done
NESTPY="$WORK/nested.py"
cat >"$NESTPY" <<'PYEOF'
import os, sys
sys.path.insert(0, sys.argv[1])
import scan
data = open(sys.argv[2], "rb").read()
with scan.Scanner(scan.Terms([], None)) as sc:
    try:
        sc.add("x", data)
    except scan.ScanError:
        print("blocked")
        sys.exit(0)
    written = sum(os.path.getsize(os.path.join(sc.src, f)) for f in os.listdir(sc.src))
print("ok" if written <= 3 * len(data) else "written %d bytes for %d" % (written, len(data)))
PYEOF
for n in 3000 10000; do
  _gen nested "$WORK/nested.txt" "$n"
  got="$("$REAL_PY" -I -B "$NESTPY" "$ROOT/public-content" "$WORK/nested.txt" 2>&1)"
  # RED WHEN: nested key blocks (many headers before one end marker) are each written out, so the
  # chunks grow with the square of the input instead of staying within a small multiple of it.
  case "$got" in ok|blocked) ok "$n nested key headers: chunks stay within 3x the input, or block ($got)" ;;
    *) bad "$n nested key headers: chunks stay within 3x the input, or block" "$got" ;; esac
done
_gen nested "$WORK/nested.txt" 3000
_text "$WORK/nested.txt"
# RED WHEN: merging nested blocks loses the key (partner: the outer block is still found).
expect_rc "nested key headers with one end marker are found" 1 "private-key at demo:1" @scanned
_gen word "$WORK/word.txt" 73971 "$(printf 'a%.0s' $(seq 29))$AGENTID"
_text "$WORK/word.txt"
# RED WHEN: a window in a long line starts at a fixed byte instead of moving back to just after
# a byte that is not a letter or digit, so a window starting at byte 74 000 invents the word
# boundary before the agent id glued to letters.
expect_rc "a long line: an agent id glued to letters at byte 74 000 is clean" 0 @scanned

echo "== (k) key blocks: one planner, a faithful copy of the private-key rule, a size bound"
# The fixtures come from one generator, so this file holds no key envelope. KELVIN is U+212A
# (Kelvin sign), LONGS U+017F (long s), DOTI U+0130 (capital I with dot), EURO U+20AC: gitleaks'
# engine folds the first two to k and s and not the third (measured, 8.30.1).
KEYGEN="$WORK/keygen.py"
cat >"$KEYGEN" <<'EOF'
import base64, random, sys
kind, out = sys.argv[1], sys.argv[2]
args = sys.argv[3:]
dash = b"-" * 5
KELVIN, LONGS, DOTI, EURO = (c.encode() for c in ("\u212a", "\u017f", "\u0130", "\u20ac"))
def body(n, wrap=b"\n"):  # n bytes of base64 of a fixed phrase, wrapped at 64: not a real key
    raw = base64.b64encode(b"not-a-real-private-key" * (n // 29 + 1))[:n]
    return wrap.join(raw[i:i + 64] for i in range(0, len(raw), 64))
def begin(label=b"", k=b"K", i=b"I"):
    return dash + b"BEG" + i + b"N " + label + b"PRIVATE " + k + b"EY" + dash
def end(k=b"K"):
    return dash + b"END PRIVATE " + k + b"EY" + dash
block, line = None, None
if kind == "blocks":  # blocks LINES: LINES lines of back-to-back 116-byte blocks, 89 900 bytes each
    blk = begin() + b"ab+/" * 16 + end()
    data = b"\n".join([blk * (89990 // len(blk))] * int(args[0]))
elif kind == "letters":  # letters N: back-to-back blocks with all-letter bodies, one line of N bytes
    blk = begin() + b"A" * 64 + end()
    data = blk * (int(args[0]) // len(blk))
elif kind == "json":  # json AT: a 4 KB key with escaped line breaks inside a JSON string from byte AT
    key = begin() + b"\\n" + body(4000, b"\\n") + b"\\n" + end() + b"\\n"
    data = b'{"pad":"' + b"x" * int(args[0]) + b'","key":"' + key + b'","more":"' + b"y" * 70000 + b'"}'
elif kind == "pemv":  # pemv AT SIZE VARIANT: a SIZE-byte body; the block starts a long line at AT
    at, size, v = int(args[0]), int(args[1]), args[2]
    b, e = {"ascii": (begin(), end()), "kelvin-begin": (begin(k=KELVIN), end()),
            "kelvin-end": (begin(), end(k=KELVIN)), "long-s": (begin(label=b"R" + LONGS + b"A "), end()),
            "dotted-i": (begin(i=DOTI), end()), "lower": (begin(label=b"RSA ").lower(), end().lower()),
            "kelvin-header": (begin(label=b"R" + KELVIN + b"A "), end())}[v]
    block = b + b"\n" + body(size) + b"\n" + e
    data = b"!" * (at - 1) + b"\n" + block + b"!" * 100000
elif kind == "pgpv":  # pgpv AT VARIANT: a PGP block whose END has the Kelvin sign in KEY or BLOCK
    at, v = int(args[0]), args[1]
    e = {"kelvin-key": b"END PGP PRIVATE " + KELVIN + b"EY BLOCK",
         "kelvin-block": b"END PGP PRIVATE KEY BLOC" + KELVIN}[v]
    block = (dash + b"BEGIN PGP PRIVATE KEY BLOCK" + dash + b"\n\n"
             + base64.encodebytes(b"not-a-real-pgp-private-key-block" * 700) + dash + e + dash)
    data = b"!" * (at - 1) + b"\n" + block + b"!" * 100000
elif kind == "euro":  # euro AT: BEGIN, 30 euro signs, END, a 25 KB body, END: one key of ~25 KB
    at = int(args[0])
    block = begin() + EURO * 30 + end() + b"\n" + body(25000) + b"\n" + end()
    data = b"!" * (at - 1) + b"\n" + block + b"!" * 100000
elif kind == "swallow":  # swallow AT: key A, its END line holding two BEGIN markers, a 25 KB key
    at = int(args[0])
    key_a = begin() + b"\n" + body(200) + b"\n" + dash + b"BEGIN" + end()
    pre = b"!" * (at - 1) + b"\n" + key_a + b" "
    data = pre + begin(label=b"RSA ") + b"\n" + body(25000) + b"\n" + end() + b"\n" + b"!" * 100000
    line = pre.count(b"\n") + 1
elif kind in ("decoy", "header", "header-alone"):  # texts with unpaired BEGIN lines; prints the line of the last key
    def filler(n):  # numbered lines of ordinary text, exactly N bytes, the last one ending in a line break
        out, i, size = [], 0, 0
        while size < n:
            out.append(b"line %06d of ordinary text here\n" % i)
            size += len(out[-1])
            i += 1
        return b"".join(out)[:n - 1] + b"\n"
    # The shorter-header block: its longest header ends at a second label, and only the shorter header has an
    # END marker 64 or more characters after it.
    short = begin() + b"Q" * 20 + b" PRIVATE " + b"KEY" + dash + b"x" * 40 + b"KEY" + dash
    word = b"fal" + b"se"
    at = 73990  # where the second window starts in this text
    head = filler(at - 200) + begin(label=b"RSA ") + b"\n" + word + b"Q" * 150 + b"\n"
    head += b"z" * (at - len(head) - 1) + b"\n"
    head += begin(label=b"RSA ") + b"\n" + word + b" " * 80 + b"\n"
    if kind == "decoy":  # a 20 KB key right after the two BEGIN lines (random base64 body, wrapped at 64)
        rnd = random.Random(7)
        al = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        raw = bytes(rnd.choice(al) for _ in range(20000))
        real = (begin(label=b"RSA ") + b"\n" + b"\n".join(raw[i:i + 64] for i in range(0, len(raw), 64)) + b"\n"
                + dash + b"END RSA PRIVATE " + b"KEY" + dash)
    elif kind == "header":  # the shorter-header block from byte 89 950, so the first window's edge cuts it
        head += filler(89950 - len(head))
        real = short
    else:
        head, real = b"", short
    line = head.count(b"\n") + 1
    data = head + real + b"\n"
    if kind != "header-alone":
        data += filler(200000 - len(data))
elif kind == "overlap":  # overlap SPACES: a percent run whose last escape starts a base64 run holding a key
    rnd = random.Random(3)
    raw = bytes(rnd.choice(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/") for _ in range(3000))
    pem = (begin(label=b"RSA ") + b"\n" + b"\n".join(raw[i:i + 64] for i in range(0, len(raw), 64)) + b"\n"
           + dash + b"END RSA PRIVATE " + b"KEY" + dash + b"\n")
    block = b"aCAg" + base64.b64encode(b"x" * 30000 + pem + b"x" * 30000)
    data = b"%41" + b" " * int(args[0]) + b"%" + block + b"\n"
elif kind == "encoded":  # encoded AT SHAPE: a 15 KB key written as SHAPE on one line from byte AT of 200 KB
    at, shape = int(args[0]), args[1]
    rnd = random.Random(3)
    al = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    raw = bytes(rnd.choice(al) for _ in range(14800))
    pem = (begin(label=b"RSA ") + b"\n" + b"\n".join(raw[i:i + 64] for i in range(0, len(raw), 64)) + b"\n"
           + dash + b"END RSA PRIVATE " + b"KEY" + dash + b"\n")
    blob = {"base64": lambda: base64.b64encode(pem), "hex": lambda: pem.hex().encode(),
            "percent": lambda: b"".join(b"%%%02X" % c for c in pem)}[shape]()
    rnd = random.Random(5)
    def words(n):
        out = b""
        while len(out) < n:
            out += b"word %d and more words here\n" % rnd.randint(0, 99999)
        return out[:n]
    head = words(at - 5) + b'x = "'
    line = head.count(b"\n") + 1
    data = head + blob + b'"\n' + words(max(0, 200000 - at - len(blob)))
else:
    sys.exit("unknown fixture " + kind)
open(out, "wb").write(data)
if block is not None:
    open(out + ".block", "wb").write(block)
    print(len(block))
if line is not None:
    print(line)
EOF
_kgen() { "$REAL_PY" -I "$KEYGEN" "$@" || die "keygen $1"; }
# gl_finds FILE RULE: real gitleaks (default rules) on FILE as one piece reports RULE.
gl_finds() { gl_rules - <"$1" | grep -q -x -F "$2"; }

# T1, T8 and T15 call the planner directly (pure Python, no gitleaks).
KEYPY="$WORK/keyplan.py"
cat >"$KEYPY" <<'EOF'
import base64, random, re, sys
sys.path.insert(0, sys.argv[1])
import scan
W, OV, E = scan.WINDOW, scan.OVERLAP, scan.EDGE
dash = "-" * 5
def report(name, good, detail=""):
    print(("ok " if good else "bad ") + name + ("" if good else " - " + detail))
def bound(n):
    return 9 * n // 4 + 2 * W
def not_whole(spans, text):
    """The plan's spans other than the whole text: a long text is also read whole, as one more
    chunk (tested on its own, in (n)); the bounds below are those of the other chunks."""
    rest = list(spans)
    if len(text) > scan.GITLEAKS_PIECE - 100 and (0, len(text)) in rest:
        rest.remove((0, len(text)))
    return rest
def keys_of(spans, wins):
    rest = list(wins)
    out = []
    for s in spans:
        if s in rest:
            rest.remove(s)
        else:
            out.append(s)
    return out

blk = (dash + "BEGIN PRIVATE KEY" + dash + "ab+/" * 16 + dash + "END PRIVATE KEY" + dash).encode()
line = blk * (89990 // len(blk))
texts = (("32 lines of back-to-back blocks", b"\n".join([line] * 32)),
         ("one 2.8 MB line of back-to-back blocks", blk * (2800000 // len(blk))))
# T1. RED WHEN: a key block starts at its line start (rfind: the spans then overlap and the
# chunk bytes grow far past 2.25 times the text).
# (Changed: every key block now gets a chunk, also one a window holds; the old wording
# named that skip as the cause.)
# (Changed: the one chunk that is the whole text is left out of the count.)
for label, text in texts:
    written = []
    with scan.Scanner(scan.Terms([], None)) as sc:
        sc._write = lambda meta, chunk, *rest, **kw: written.append(len(chunk))
        try:
            sc.add("demo", text)
            if len(text) in written:
                written.remove(len(text))
            report("T1: %s: chunk bytes within 9n/4 + 2W" % label, sum(written) <= bound(len(text)),
                   "%d bytes in %d chunks for %d" % (sum(written), len(written), len(text)))
        except scan.ScanError as exc:
            report("T1: %s: chunk bytes within 9n/4 + 2W" % label, False, "ScanError: %s" % exc)
# T1 (plan). RED WHEN: as above, or key spans overlap, or they are not grouped (one chunk per
# 116-byte block), so there are more chunks than n/72 000 + n/14 000 + 2.
for label, text in texts:
    name = "T1: %s: the plan's key spans are disjoint and within the bound" % label
    try:
        spans, too_long = scan._plan(text)
    except AttributeError as exc:
        report(name, False, "no planner (%s)" % exc)
        continue
    spans = not_whole(spans, text)
    keys = sorted(keys_of(spans, scan._windows(text)))
    n = len(text)
    good = (sum(e - s for s, e in spans) <= bound(n) and not too_long
            and all(a[1] <= b[0] for a, b in zip(keys, keys[1:]))
            and len(spans) <= n / 72000 + n / 14000 + 2)
    report(name, good, "%d spans, %d key spans, %d bytes, too long %s" % (
        len(spans), len(keys), sum(e - s for s, e in spans), too_long))

# T8. RED WHEN: the planner's size check is removed, or its bound is not 25n/4 + WINDOW (the
# derived bound below, now that encoded runs inside a long merged span are read as pieces of
# their own): fourteen full windows over 200 000 bytes (1 260 000) must pass it, fifteen
# (1 350 000) must not.
# (Changed: the bound was 13n/4 + 2 * WINDOW before such runs got pieces of their own.)
# (Changed: overlapping key spans are now merged into one span, so the old fixture, 100
# copies of one span, no longer reaches the check; the windows are patched instead.)
# (A long text is also read whole: that chunk's n bytes are counted on both sides, in the plan and
# in its size check, so the same window counts pass and fail.)
text = b"!" * 200000
n = len(text)
real_w = scan._windows
for k, want_error in ((25 * n // 4 + W) // W + 1, True), ((25 * n // 4 + W) // W, False):
    name = "T8: the planner %s %d full windows over %d bytes (bound 25n/4 + W)" % (
        "refuses" if want_error else "accepts", k, n)
    try:
        scan._windows = lambda t, k=k: [(0, W)] * k
        scan._plan(text)
        report(name, not want_error, "no error")
    except scan.ScanError as exc:
        report(name, want_error and "exceeds its size bound" in str(exc), "error: %s" % exc)
    except AttributeError as exc:
        report(name, False, "no planner (%s)" % exc)
    finally:
        scan._windows = real_w
# T8b. RED WHEN: overlapping spans are each chunked instead of merged into their union (a
# span is then counted once per copy and the plan fails its own size check).
real = scan._key_spans
try:
    scan._key_spans = lambda t: [(80000, 170000)] * 100
    spans, too_long = scan._plan(text)
    extra = keys_of(not_whole(spans, text), scan._windows(text))
    report("T8b: 100 copies of one key span are read as one chunk", extra == [(80000, 170000)] and not too_long,
           "extra chunks %s, too long %s" % (extra[:3], too_long))
except scan.ScanError as exc:
    report("T8b: 100 copies of one key span are read as one chunk", False, "ScanError: %s" % exc)
finally:
    scan._key_spans = real

# T15. An oracle: the whole private-key rule as a str regex on surrogateescape text, with the
# fold classes of gitleaks' engine written out (k, K, Kelvin sign; s, S, long s). Slow; test only.
def fold(ch):
    alts = [ch.lower(), ch.upper()] + (["\u212a"] if ch.lower() == "k" else []) + (["\u017f"] if ch.lower() == "s" else [])
    return "(?:" + "|".join(map(re.escape, alts)) + ")"
def lit(w):
    return "".join(fold(c) if c.isalpha() else re.escape(c) for c in w)
TAIL = "(?: " + lit("BLOCK") + ")?" + dash
ORACLE = re.compile(dash + lit("BEGIN") + "(?:[ A-Za-z0-9_\\-]|\u017f|\u212a){0,100}" + lit("PRIVATE KEY") + TAIL
                    + "[\\s\\S]{64,}?" + lit("KEY") + TAIL)
def oracle(text):
    s = text.decode("utf-8", "surrogateescape")
    off = [0]
    for c in s:
        off.append(off[-1] + len(c.encode("utf-8", "surrogateescape")))
    return [(off[m.start()], off[m.end()]) for m in ORACLE.finditer(s)]
rnd = random.Random(20261117)
table = bytes(b"Ab+/\n"[i % 5] for i in range(256))
pieces = [p.encode("utf-8", "surrogateescape") for p in (
    dash + "BEGIN PRIVATE KEY" + dash, dash + "BEGIN RSA PRIVATE KEY" + dash,
    dash + "BEGIN PRIVATE \u212aEY" + dash, dash + "BEGIN \u017fX PRIVATE KEY" + dash,
    dash + "BEGIN PGP PRIVATE KEY BLOCK" + dash, dash + "END PRIVATE KEY" + dash, "KEY" + dash,
    "KEY BLOCK" + dash, "\u212aEY" + dash, dash + "BEGIN ", " PRIVATE KEY" + dash, dash + "BEGIN" + dash + "BEGIN",
    "\u20ac", "\udcff", "\u0130", "-", "\n", "A" * 10, "ab+/", dash + "begin private key" + dash,
    dash + "begin rsa private key" + dash, dash + "end private key" + dash, "key" + dash, "key block" + dash,
    dash + "Begin Private Key Block" + dash)] + [b"\xe2\x84"]
# T15. RED WHEN: _windows advances by more than WINDOW - OVERLAP + EDGE, the chunks beside the
# windows overlap, body_end counts bytes, a key match is left to the windows alone (every
# match of at most WINDOW bytes must lie inside a chunk of its own group), or a chunk is cut inside a
# match (the rule on each such chunk finds exactly the whole text's matches inside it).
# (Changed: the clause "no window holds a key span whole" is removed; every key span now
# has a chunk, so that clause fails on the fixed planner. A text whose merged spans are too long
# is left out of these two checks and counted.)
# (Changed: these bounds are those of the chunks other than the one that is the whole text.)
fails = []
too_long_texts = 0
for it in range(300):
    parts = []
    while sum(map(len, parts)) < 130000:
        r = rnd.random()
        if r < 0.15:
            parts.append(rnd.randbytes(rnd.randint(64, 40000)).translate(table))
        elif r < 0.25:
            parts.append(b"x" * rnd.randint(1, 30000))
        else:
            parts.append(rnd.choice(pieces))
    text = b"".join(parts)
    try:
        spans, too_long = scan._plan(text)
    except AttributeError as exc:
        fails.append("no planner (%s)" % exc)
        break
    spans = not_whole(spans, text)
    wins = scan._windows(text)
    keys = sorted(keys_of(spans, wins))
    n = len(text)
    # The windows cover the text, each at most WINDOW bytes, each starting at least
    # WINDOW - OVERLAP - EDGE after the one before and at least OVERLAP - EDGE before it ends.
    wins_ok = (wins[0][0] == 0 and wins[-1][1] == n and all(e - s <= W for s, e in wins)
          and all(b[0] - a[0] >= W - OV - E and b[0] <= a[1] - (OV - E) for a, b in zip(wins, wins[1:])))
    # The chunks beside the windows are at most WINDOW bytes, and all chunks keep the derived
    # bounds (25n/4 + WINDOW bytes; see the derivation below). (Changed: these chunks had to be
    # disjoint; encoded runs inside a long merged span are now pieces of their own and may overlap.)
    keys_ok = (all(e - s <= W for s, e in keys) and sum(e - s for s, e in spans) <= 25 * n // 4 + W
               and len(spans) <= n / 72000 + 2 * n / W + n / 3000 + 3)
    found = oracle(text)
    # A flagged text blocks whole, so a match inside a merged span over WINDOW needs no chunk.
    missed = [] if too_long else [m for m in found if m[1] - m[0] <= W and not any(s <= m[0] and m[1] <= e for s, e in spans)]
    longer = [m for m in found if m[1] - m[0] > W]
    own = inexact = 0
    if too_long:
        too_long_texts += 1
    else:
        own = sum(1 for m in found if not any(s <= m[0] and m[1] <= e for s, e in keys))
        for s, e in keys:
            inside = [(a - s, b - s) for a, b in found if s <= a and b <= e]
            if oracle(text[s:e]) != inside:
                inexact += 1
    if not (wins_ok and keys_ok) or missed or (longer and not too_long) or own or inexact:
        fails.append("text %d: windows %s, chunks %s, %d oracle matches in no chunk, %d too long (flag %s), "
                     "%d matches in no chunk of their own, %d inexact chunks" % (
                         it, wins_ok, keys_ok, len(missed), len(longer), too_long, own, inexact))
report("T15: 300 fuzz texts: every oracle match lies in a chunk of its own group, read exactly; windows and chunks "
       "keep their bounds", not fails and too_long_texts <= 50,
       "; ".join(fails[:3]) + (" (%d texts)" % len(fails) if fails else "") + " (%d too long)" % too_long_texts)

# Key spans. RED WHEN: _key_spans skips a BEGIN marker whose longest header has no END marker after it
# instead of trying the shorter headers its line allows, as Go's regexp does, or its END
# distance is off by a character. The oracle is the full rule above, which backtracks the same way.
# The distance runs from the end of the header, just after its closing five dashes.
pieces3 = pieces + [p.encode() for p in (
    dash + "BEGIN PRIVATE KEY" + dash + "Q" * 20 + " PRIVATE KEY" + dash, "x" * 40 + "KEY" + dash,
    "Q" * 50, " PRIVATE KEY" + dash, "x KEY" + dash, dash + "BEGIN RSA PRIVATE KEY" + dash + " PRIVATE KEY" + dash)]
rnd3 = random.Random(20261119)
diff3 = []
for it in range(5000):
    parts = []
    while sum(map(len, parts)) < 600:
        r = rnd3.random()
        parts.append(rnd3.randbytes(rnd3.randint(1, 120)).translate(table) if r < 0.2 else rnd3.choice(pieces3))
    text = b"".join(parts)
    if scan._key_spans(text) != oracle(text):
        diff3.append(it)
report("Key spans: on 5 000 fuzz texts the key spans equal the full rule's matches", not diff3,
       "%d texts differ, first %s" % (len(diff3), diff3[:5]))
# Key spans partner. RED WHEN: the distance is measured from the BEGIN marker's start or from the end of
# its longest header: 64 characters from the header's closing dashes to the K of KEY is a key, 63 is not.
for body_len, want in ((64, 1), (63, 0)):
    text = (dash + "BEGIN PRIVATE KEY" + dash + "a" * (body_len - len("x ")) + "x KEY" + dash).encode()
    got = scan._key_spans(text)
    report("Key spans partner: a %d-character body %s a key" % (body_len, "is" if want else "is not"),
           len(got) == want and len(oracle(text)) == want, "spans %s, oracle %s" % (got, oracle(text)))

# The chunks beside the windows ("extra" chunks) of a plan.
def extra_chunks(text):
    spans, too_long = scan._plan(text)
    spans = not_whole(spans, text)
    return spans, keys_of(spans, scan._windows(text)), too_long
def inside(span, chunks):
    return any(s <= span[0] and span[1] <= e for s, e in chunks)
def count_bound(n):  # windows <= n/72 000 + 1; groups < 2n/WINDOW + 2 (derived below)
    return n / 72000 + 2 * n / W + 3
# Derivation: windows start at least WINDOW - OVERLAP - EDGE = 72 000 bytes apart, so there
# are at most n/72 000 + 1, each at most WINDOW bytes: at most 5n/4 + WINDOW bytes. Groups are
# disjoint, so they add up to at most n bytes. A group starts at a merged span's start and the
# next group starts at the first span that would end more than WINDOW bytes after that start, so
# group k + 2 starts more than WINDOW bytes after group k: fewer than 2n/WINDOW + 2 groups.
# Long spans. RED WHEN: a long run of encoded text gets no chunk of its own, a merged span is counted
# twice, or groups are not packed (the dense case then needs one chunk per run).
text = (b"Q" * 12004 + b"\n") * 100
n = len(text)
spans, extra, too_long = extra_chunks(text)
runs = [(i * 12005, i * 12005 + 12004) for i in range(100)]
report("Long spans: 100 encoded runs of 12 004 bytes each lie inside a chunk of their own",
       all(inside(r, extra) for r in runs) and not too_long,
       "%d of 100 runs in an extra chunk, too long %s" % (sum(inside(r, extra) for r in runs), too_long))
report("Long spans: the dense case keeps the byte and chunk bounds (extra chunks disjoint, at most n bytes)",
       sum(e - s for s, e in spans) <= 9 * n // 4 + 2 * W and sum(e - s for s, e in extra) <= n
       and len(spans) <= count_bound(n) and all(a[1] <= b[0] for a, b in zip(extra, extra[1:])),
       "%d chunks (bound %.0f), %d bytes, %d extra bytes for %d" % (
           len(spans), count_bound(n), sum(e - s for s, e in spans), sum(e - s for s, e in extra), n))
for glued in (False, True):
    rnd4 = random.Random(41)
    blocks, keyspans, pos = [], [], 0
    for i in range(100):
        body = bytes(rnd4.choice(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/") for _ in range(12500))
        blk = (dash + "BEGIN PRIVATE KEY" + dash).encode() + (b"" if glued else b"\n") + body + b"\n" \
            + (dash + "END PRIVATE KEY" + dash).encode()
        pad = (b"a few words of text\n" * (1 + i % 5))
        keyspans.append((pos + len(pad), pos + len(pad) + len(blk)))
        blocks.append(pad + blk)
        pos += len(pad) + len(blk)
    text = b"".join(blocks) + b"\n"
    n = len(text)
    spans, extra, too_long = extra_chunks(text)
    label = "glued to its header" if glued else "on its own line"
    report("Long spans: 100 key blocks whose 12 500-byte body (%s) is an encoded run: each read whole, counted once" % label,
           scan._key_spans(text) == keyspans and all(inside(k, extra) for k in keyspans) and not too_long
           and sum(e - s for s, e in extra) <= n and len(spans) <= count_bound(n)
           and sum(e - s for s, e in spans) <= 9 * n // 4 + 2 * W,
           "%d of 100 in an extra chunk, %d chunks (bound %.0f), %d extra bytes for %d, too long %s" % (
               sum(inside(k, extra) for k in keyspans), len(spans), count_bound(n),
               sum(e - s for s, e in extra), n, too_long))

# Encoded runs. RED WHEN: a run of encoded text longer than OVERLAP - 2 * EDGE (12 000) bytes, in one of the
# shapes gitleaks 8.30.1 decodes, gets no chunk of its own: gitleaks decodes it before it matches,
# so a match inside it is as long as the run. Shapes measured on 8.30.1 (its own patterns):
# base64 [\w/+-]{16,}={0,2}, hex [0-9A-Fa-f]{32,}, percent %XX(.*%XX)? (first to last escape of a
# line) and Unicode escapes (\uXXXX, \\uXXXX, or U+XXXX followed by a space).
def words_text(at, run, total=200000):
    head = (b"some words of text\n" * (at // 19 + 1))[:at - 1] + b"\n"
    return head + run + b"\n" + (b"more words of text\n" * ((total - at) // 19 + 1))[:max(0, total - at - len(run))]
for label, run in (("base64", b"QUJD" * 3000 + b"QQ=="), ("hex", b"0a1B" * 3001),
                   ("percent, escapes only", b"%41" * 4001),
                   ("percent, text between the first and last escape", b"%41 " + b"plain words " * 1000 + b"%41"),
                   ("backslash-u escapes", b"\\u0041" * 2001), ("U+ escapes", b"U+0041 " * 1715)):
    text = words_text(71999, run)
    at = 71999
    spans, extra, too_long = extra_chunks(text)
    report("Encoded runs: a %d-byte %s run from byte 71 999 lies inside a chunk of its own" % (len(run), label),
           len(run) > 12000 and inside((at, at + len(run)), extra) and not too_long,
           "extra chunks %s, too long %s" % (extra[:4], too_long))
# Encoded runs partner. RED WHEN: an encoded run longer than WINDOW sets the too-long flag (it must
# never block: it is read in the ordinary windows), or its windows stop covering the text.
# (Changed: this case expected the flag before the owner's answer on long encoded runs.)
text = words_text(50000, b"QUJD" * 22501)
spans, extra, too_long = extra_chunks(text)
wins = scan._windows(text)
report("Encoded runs partner: a 90 004-byte base64 run does not set the too-long flag and is read in the windows",
       too_long is False and wins[0][0] == 0 and wins[-1][1] == len(text) and all(w in spans for w in wins),
       "too long %s, %d windows" % (too_long, len(wins)))
# Encoded runs partner. RED WHEN: a raw key block longer than WINDOW no longer sets the flag (it still blocks).
big = (dash + "BEGIN PRIVATE KEY" + dash + "\n").encode() + (b"QUJD" * 16 + b"\n") * 1400 \
    + (dash + "END PRIVATE KEY" + dash).encode()
text = words_text(50000, big)
report("Encoded runs partner: a %d-byte raw key block sets the too-long flag" % len(big), len(big) > W and extra_chunks(text)[2] is True,
       "too long %s" % extra_chunks(text)[2])
# Touching spans. RED WHEN: either key block is not read whole in a chunk of its own, or the pair
# sets the too-long flag. (Merging spans that only touch does not turn it red: each block is still
# read whole as a key block of the longer merged span; that mutant is equivalent.)
half = (dash + "BEGIN PRIVATE KEY" + dash + "\n").encode() + (b"QUJD" * 16 + b"\n") * 735 \
    + (dash + "END PRIVATE KEY" + dash).encode()
text = words_text(50000, half + half)
spans, extra, too_long = extra_chunks(text)
k0 = (50000, 50000 + len(half))
k1 = (k0[1], k0[1] + len(half))
report("Touching spans: two touching key blocks of %d bytes are read whole, apart, with no flag" % len(half),
       too_long is False and inside(k0, extra) and inside(k1, extra), "too long %s, extra %s" % (too_long, extra[:4]))
# Long merged span. RED WHEN: a merged span longer than WINDOW sets the flag although each key block in it is
# at most WINDOW bytes, or a key block in it gets no chunk of its own: here two 48 000-byte key
# blocks whose bodies are one encoded run each, joined by a 13 000-byte encoded run overlapping both.
def body_key(n):
    return (dash + "BEGIN PRIVATE KEY" + dash).encode() + b"QUJD" * (n // 4) + (dash + "END PRIVATE KEY" + dash).encode()
ka = body_key(48000)
kb = body_key(48000)
text = words_text(50000, ka + b"QUJD" * 3250 + kb)
k0 = (50000, 50000 + len(ka))
k1 = (50000 + len(ka) + 13000, 50000 + len(ka) + 13000 + len(kb))
spans, extra, too_long = extra_chunks(text)
merged_len = k1[1] - k0[0]
report("Long merged span: a %d-byte merged span of two key blocks sets no flag and each block is read whole" % merged_len,
       merged_len > W and scan._key_spans(text) == [k0, k1] and too_long is False and inside(k0, extra)
       and inside(k1, extra), "key spans %s, too long %s, extra %s" % (scan._key_spans(text)[:3], too_long, extra[:4]))

# The encoded runs a plan must read whole: the shapes gitleaks 8.30.1 decodes, each run longer
# than OVERLAP - 2 * EDGE and at most WINDOW bytes (written here, apart from scan.py, as the test's
# own copy of the measured patterns).
SHAPES = (re.compile(rb"[A-Za-z0-9_/+-]{16,}={0,2}"), re.compile(rb"[0-9A-Fa-f]{32,}"),
          re.compile(rb"%[0-9A-Fa-f]{2}(?:[^\n]*%[0-9A-Fa-f]{2})?"),
          re.compile(rb"(?:(?:U\+[a-fA-F0-9]{4}(?:[\t\n\f\r ]|$))+|(?i:(?:\\{1,2}u[a-fA-F0-9]{4})+))"))
def runs_of(text):
    return sorted({m.span() for rx in SHAPES for m in rx.finditer(text) if OV - 2 * E < m.end() - m.start() <= W})
# Derived bounds once encoded runs inside a merged span longer than WINDOW are read as pieces of
# their own (pieces may then overlap). Windows: at most n/72 000 + 1 of them and 5n/4 + WINDOW
# bytes. Groups (merged spans of at most WINDOW bytes, and the key blocks of longer ones) never
# overlap: at most n bytes and fewer than 2n/WINDOW + 2 of them. Runs read on their own: the runs
# of one shape never overlap, so each of the four shapes adds at most n bytes and, each run being
# longer than 12 000 bytes, at most n/12 000 pieces. Total: at most 25n/4 + WINDOW bytes in fewer
# than n/72 000 + 2n/WINDOW + n/3 000 + 3 chunks.
def bound25(n):
    return 25 * n // 4 + W
def count25(n):
    return n / 72000 + 2 * n / W + n / 3000 + 3
def plan_report(name, text, must_hold, key=None):
    try:
        spans, extra, too_long = extra_chunks(text)
    except scan.ScanError as exc:
        report(name, False, "ScanError: %s" % exc)
        return
    n = len(text)
    lost = [r for r in must_hold if not inside(r, extra)]
    size = sum(e - s for s, e in spans)
    report(name, not lost and not too_long and size <= bound25(n) and len(spans) <= count25(n),
           "%d of %d runs or keys in no chunk of their own (first %s), too long %s, %d bytes (bound %d), %d chunks "
           "(bound %.0f)" % (len(lost), len(must_hold), lost[:2], too_long, size, bound25(n), len(spans), count25(n)))
# A synthetic key, assembled at run time: a 3 000-character random base64 body wrapped at 64, between
# 30 000 x's on each side (its base64 run is about 84 000 bytes).
rnd5 = random.Random(3)
body5 = bytes(rnd5.choice(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/") for _ in range(3000))
pem5 = ((dash + "BEGIN RSA PRIVATE KEY" + dash + "\n").encode()
        + b"\n".join(body5[i:i + 64] for i in range(0, len(body5), 64)) + b"\n"
        + (dash + "END RSA PRIVATE KEY" + dash + "\n").encode())
blob5 = base64.b64encode(b"x" * 30000 + pem5 + b"x" * 30000)
# Overlapping runs. RED WHEN: an encoded run of at most WINDOW bytes inside a merged span longer
# than WINDOW is left to the windows (it then lies whole in none, and its key is missed): a
# percent run from the first escape of a line to its last, whose last escape starts a base64 run
# that holds a key. The space count moves the runs against the window edges.
for spaces in (50000, 50001, 50002, 50003):
    prefix = b"%41" + b" " * spaces + b"%"
    text = prefix + b"aCAg" + blob5 + b"\n"
    want = [(0, len(prefix) + 2), (len(prefix), len(prefix) + 4 + len(blob5))]
    plan_report("Overlapping runs: with %d spaces the percent run and the %d-byte base64 run each lie whole in a chunk "
                "of their own" % (spaces, len(blob5)), text, want)
# Overlapping runs, dense. RED WHEN: the runs of a long merged span are left to the windows, or
# the plan's size check is lower than the derived bound (it then refuses this text): every line
# holds a 60 000-byte percent run whose last escape starts an 80 000-byte hex run, and hex runs are
# base64 runs too, so every byte is in up to three runs.
hexes = (b"0123456789abcdef" * 6000)
line = b"%41" + hexes[:59990] + b"%aB" + hexes[:79990] + b"\n"
text = line * 10
plan_report("Overlapping runs, dense: 10 lines of a 60 000-byte percent run overlapping an 80 000-byte hex run",
            text, runs_of(text))
# Touching runs. RED WHEN: the 60 000-byte key block or the 40 006-byte percent run starting where
# it ends is not read whole in a chunk of its own. (Merging touching spans is an equivalent mutant
# here: the merged span is longer than WINDOW, and each is still read whole on its own.)
rnd6 = random.Random(6)
body6 = bytes(rnd6.choice(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/") for _ in range(58000))
key6 = ((dash + "BEGIN PRIVATE KEY" + dash + "\n").encode() + b"\n".join(body6[i:i + 64] for i in range(0, len(body6), 64))
        + b"\n" + (dash + "END PRIVATE KEY" + dash).encode())
pct6 = b"%41" + b"!" * 40000 + b"%41"
text = b"words of text\n" * 100 + key6 + pct6 + b"\n" + b"more words\n" * 1000
at6 = 1400
plan_report("Touching runs: a %d-byte key block and the percent run touching it each lie whole in a chunk of their own"
            % len(key6), text, [(at6, at6 + len(key6)), (at6 + len(key6), at6 + len(key6) + len(pct6))])
# Touching runs partner. RED WHEN: the 63 000-byte run of U+ escapes or the 42 006-byte percent run
# starting where it ends is not read whole in a chunk of its own (merging touching runs is an
# equivalent mutant, as above).
text = b"U+0041 " * 9000 + b"%41" + b"!" * 42000 + b"%41"
plan_report("Touching runs: a U+ escape run and the percent run touching it each lie whole in a chunk of their own",
            text, [(0, 63000), (63000, 105006)])
EOF
# py_verdicts PY ARGS...: run a Python check and turn its `ok NAME` / `bad NAME - DETAIL` lines into verdicts.
py_verdicts() {
  local out="$WORK/py-verdicts.txt" verdict rest
  "$REAL_PY" -I -B "$@" >"$out" 2>&1 || { bad "$(basename "$1") ran" "exit $?: $(tail -c 300 "$out" | tr '\n' ' ')"; return; }
  while IFS= read -r ln; do
    verdict="${ln%% *}"
    rest="${ln#* }"
    case "$verdict" in
      ok) ok "$rest" ;;
      bad) bad "${rest%% - *}" "${rest#* - }" ;;
      *) bad "$(basename "$1") output" "$ln" ;;
    esac
  done <"$out"
}
py_verdicts "$KEYPY" "$ROOT/public-content"

_kgen blocks "$WORK/blocks2.txt" 2
_text "$WORK/blocks2.txt"
# T1b. RED WHEN: blocks a window holds are skipped AND windows shrink below the block size, so
# the planner's savings would hide real keys (proves T1 counts real findings).
expect_rc "T1b: back-to-back blocks on two long lines are found on both" 1 "private-key at demo:1" "private-key at demo:2" @scanned
_kgen letters "$WORK/letters.txt" 300000
_text "$WORK/letters.txt"
# T2. RED WHEN: key spans start at the line start (each block then measures from byte 0 and the
# check blocks with "crosses a scan window").
expect_rc "T2: a 300 KB line of all-letter key blocks is found" 1 "private-key at demo:1" @scanned
_kgen json "$WORK/json.txt" 100000
_text "$WORK/json.txt"
# T3. RED WHEN: a block's length is measured from its line start (a 4 KB key at byte 100 000 of
# a JSON line then counts as 104 KB).
expect_rc "T3: a 4 KB key with escaped line breaks inside a 174 KB JSON line is found" 1 "private-key at demo:1" @scanned
for v in ascii kelvin-begin kelvin-end long-s kelvin-header lower; do
  _kgen pemv "$WORK/pemv.txt" 70000 50000 "$v" >/dev/null
  # RED WHEN: the fixture stops being a key gitleaks itself reports when read whole.
  if gl_finds "$WORK/pemv.txt.block" private-key; then ok "T4: gitleaks reports the $v block read whole"; else
    bad "T4: gitleaks reports the $v block read whole" "not reported"; fi
  _text "$WORK/pemv.txt"
  # T4. RED WHEN: the U+212A or U+017F alternative is removed from the marker regexes (in a
  # marker word or in the header class), they become a str (?i) regex, or a marker letter stops
  # matching its ASCII lower case (the lower variant).
  expect_rc "T4: a 50 KB key ($v) from byte 70 000 of a long line is found" 1 "private-key at demo:2" @scanned
done
_kgen pemv "$WORK/pemv.txt" 70000 50000 dotted-i >/dev/null
# RED WHEN: the fixture changes so that gitleaks reports it read whole (the partner below would
# then no longer show a fold gitleaks does not make).
if gl_finds "$WORK/pemv.txt.block" private-key; then bad "T4: gitleaks does not report a BEGIN with a dotted capital I" "reported"; else
  ok "T4: gitleaks does not report a BEGIN with a dotted capital I"; fi
_text "$WORK/pemv.txt"
# T4 partner. RED WHEN: the marker regex folds U+0130 to i, which gitleaks does not (a str (?i) regex).
expect_rc "T4: a key whose BEGIN has a dotted capital I is clean, as in gitleaks" 0 @scanned
for v in kelvin-key kelvin-block; do
  _kgen pgpv "$WORK/pgpv.txt" 70000 "$v" >/dev/null
  # RED WHEN: the fixture stops being a key gitleaks itself reports when read whole.
  if gl_finds "$WORK/pgpv.txt.block" private-key; then ok "T5: gitleaks reports the PGP $v block read whole"; else
    bad "T5: gitleaks reports the PGP $v block read whole" "not reported"; fi
  _text "$WORK/pgpv.txt"
  # T5. RED WHEN: the K alternative is missing from the END regex (in KEY or in BLOCK).
  expect_rc "T5: a PGP key whose END has a Kelvin sign ($v) is found" 1 "private-key at demo:2" @scanned
done
_kgen euro "$WORK/euro.txt" 70000 >/dev/null
# RED WHEN: the fixture stops being a key gitleaks itself reports when read whole.
if gl_finds "$WORK/euro.txt.block" private-key; then ok "T6: gitleaks reports the euro-sign block read whole"; else
  bad "T6: gitleaks reports the euro-sign block read whole" "not reported"; fi
_text "$WORK/euro.txt"
# T6. RED WHEN: body_end counts bytes, not characters (the span then ends at the first END and
# gitleaks' real 25 KB match is cut between two windows).
expect_rc "T6: a key whose first END is under 64 characters after BEGIN is found" 1 "private-key at demo:2" @scanned
# The 64-character body at a window edge. The body runs from the end of the BEGIN marker to the
# K of the END marker: a line break, SIZE base64 characters, a line break and the 17 characters
# of the END marker before KEY, so SIZE 44 gives 63 characters and SIZE 45 gives 64. The block
# starts at byte 89 950, so the first window's edge (about byte 90 000) cuts it.
for size in 44 45; do
  runes=$((size + 19))
  _kgen pemv "$WORK/pemb.txt" 89950 "$size" ascii >/dev/null
  _text "$WORK/pemb.txt"
  if [ "$size" = 45 ]; then
    # RED WHEN: the fixture stops being a key gitleaks itself reports when read whole.
    if gl_finds "$WORK/pemb.txt.block" private-key; then ok "T6b: gitleaks reports the $runes-character body read whole"; else
      bad "T6b: gitleaks reports the $runes-character body read whole" "not reported"; fi
    # T6b. RED WHEN: a block a window edge cuts is in no chunk whole (windows stop overlapping
    # by more than the block), so the 64-character key is missed.
    expect_rc "T6b: a block with a $runes-character body across a window edge is found" 1 "private-key at demo:2" @scanned
  else
    # RED WHEN: the fixture changes so that gitleaks reports a 63-character body (the clean case
    # below would then test nothing).
    if gl_finds "$WORK/pemb.txt.block" private-key; then bad "T6b: gitleaks does not report a $runes-character body" "reported"; else
      ok "T6b: gitleaks does not report a $runes-character body"; fi
    # T6b. RED WHEN: the guard reports a block gitleaks does not report read whole (a chunk
    # boundary inside the block making a key of it). KEY_MIN_BODY off by one does not turn this
    # red, because a window holds the block whole; T15's oracle guards that (measured).
    expect_rc "T6b: a block with a $runes-character body across a window edge is clean" 0 @scanned
  fi
done
sline="$(_kgen swallow "$WORK/swallow.txt" 68000)"
_text "$WORK/swallow.txt"
# T15b. RED WHEN: BEGIN markers are found with finditer (the greedy header of a BEGIN inside key
# A swallows the next real BEGIN, and its 25 KB key is in no chunk).
expect_rc "T15b: a key after a line holding two BEGIN markers is found with the key before it" 1 \
  "private-key at demo:2" "private-key at demo:$sline" @scanned

# gl_whole FILE: "RULE LINE" of each finding of real gitleaks (default rules) reading FILE whole
# (gitleaks dir on a folder holding only FILE).
gl_whole() {
  if ! { rm -rf "$WORK/glw" && mkdir -p "$WORK/glw" && cp "$1" "$WORK/glw/f.txt"; }; then die "gl_whole $1"; fi
  "$REAL_GITLEAKS" dir "$WORK/glw" --no-banner --redact --report-format json --report-path "$WORK/glw.json" \
    --exit-code 0 >/dev/null 2>&1 || die "gitleaks dir"
  "$REAL_PY" -I -c 'import json,sys; [print(f["RuleID"], f["StartLine"]) for f in json.load(open(sys.argv[1]))]' "$WORK/glw.json"
}
# The next two cases use one text shape: two BEGIN lines that pair with no END of their own, the second one
# at the second window's start, then a key (measured with gitleaks 8.30.1 at the plan stage).
dline="$(_kgen decoy "$WORK/decoy.txt")"
# RED WHEN: the fixture stops being a key that gitleaks itself reports, on its BEGIN line, read whole.
if gl_whole "$WORK/decoy.txt" | grep -q -x -F "private-key $dline"; then ok "Unpaired BEGIN lines: gitleaks reads the text with unpaired BEGIN lines whole and reports line $dline"; else
  bad "Unpaired BEGIN lines: gitleaks reads the text with unpaired BEGIN lines whole and reports line $dline" "$(gl_whole "$WORK/decoy.txt" | tr '\n' ' ')"; fi
_text "$WORK/decoy.txt"
# Unpaired BEGIN lines. RED WHEN: a key block that a window holds whole gets no chunk of its own (the held-span skip
# comes back): a window can read the text before a block differently from the whole text.
expect_rc "Unpaired BEGIN lines: a 20 KB key after two unpaired BEGIN lines is found on its own line" 1 "private-key at demo:$dline" @scanned
hline="$(_kgen header "$WORK/header.txt")"
# RED WHEN: the fixture stops being a key that gitleaks itself reports, on its BEGIN line, read whole.
if gl_whole "$WORK/header.txt" | grep -q -x -F "private-key $hline"; then ok "Shorter header: gitleaks reads the shorter-header text whole and reports line $hline"; else
  bad "Shorter header: gitleaks reads the shorter-header text whole and reports line $hline" "$(gl_whole "$WORK/header.txt" | tr '\n' ' ')"; fi
_text "$WORK/header.txt"
# Shorter header. RED WHEN: the shorter-header retry is removed from _key_spans: the block is then no key
# span, so it gets no chunk of its own, and the first window's edge cuts it.
expect_rc "Shorter header: a key whose longest header has no END marker is found from byte 89 950" 1 "private-key at demo:$hline" @scanned
_kgen header-alone "$WORK/header-alone.txt" >/dev/null
_text "$WORK/header-alone.txt"
# Shorter header partner. RED WHEN: the block stops being a key gitleaks reports (the case above would then test nothing).
expect_rc "Shorter header partner: the same block alone in a small file is found" 1 "private-key at demo:1" @scanned
# Encoded runs (end to end). A 15 KB key written as one line of base64, hex or percent escapes, from byte
# 71 999 of 200 KB: the edges of the first two windows both cut it.
for shape in base64 hex percent; do
  eline="$(_kgen encoded "$WORK/enc.txt" 71999 "$shape")"
  # RED WHEN: the fixture stops being a key gitleaks reports on that line when it reads the text whole.
  if gl_whole "$WORK/enc.txt" | grep -q -x -F "private-key $eline"; then ok "Encoded runs: gitleaks reads the $shape key text whole and reports line $eline"; else
    bad "Encoded runs: gitleaks reads the $shape key text whole and reports line $eline" "$(gl_whole "$WORK/enc.txt" | tr '\n' ' ')"; fi
  _text "$WORK/enc.txt"
  # Encoded runs. RED WHEN: a long run of encoded text gets no chunk of its own, so a key gitleaks finds
  # only after decoding the whole run is cut by a window edge.
  expect_rc "Encoded runs: a $shape-encoded key from byte 71 999 is found" 1 "private-key at demo:$eline" @scanned
  eline="$(_kgen encoded "$WORK/enc.txt" 99999 "$shape")"
  _text "$WORK/enc.txt"
  # Encoded runs partner. RED WHEN: the encoded key is no longer found where a window holds it whole.
  expect_rc "Encoded runs partner: the $shape-encoded key from byte 99 999 is found" 1 "private-key at demo:$eline" @scanned
done
"$REAL_PY" -I -c 'import sys; sys.stdout.write("some words of text\n" * 2632 + "QUJD" * 22501 + "\n" + "more words of text\n" * 5000)' >"$WORK/longrun.txt"
_text "$WORK/longrun.txt"
# Encoded runs partner. RED WHEN: an encoded run longer than 90 000 bytes blocks the check (exit 2)
# instead of being read in the ordinary windows.
expect_rc "Encoded runs partner: a clean text holding a 90 004-byte base64 run is not blocked" 0 @scanned
for spaces in 50000 50001 50002 50003; do
  _kgen overlap "$WORK/overlap.txt" "$spaces" >/dev/null
  # RED WHEN: the fixture stops being a key gitleaks reports when it reads the base64 run alone.
  if gl_finds "$WORK/overlap.txt.block" private-key; then ok "Overlapping runs: gitleaks reports the base64 run read alone ($spaces spaces)"; else
    bad "Overlapping runs: gitleaks reports the base64 run read alone ($spaces spaces)" "not reported"; fi
  _text "$WORK/overlap.txt"
  # Overlapping runs (end to end). RED WHEN: an encoded run of at most 90 000 bytes inside a merged
  # span longer than that is left to the windows, which cut it, so its key is missed.
  expect_rc "Overlapping runs: the key in a base64 run overlapping a percent run is found ($spaces spaces)" 1 \
    "private-key at demo:1" @scanned
done

echo "== (l) private terms: one fold, one word test"
TERMPY="$WORK/terms.py"
cat >"$TERMPY" <<'EOF'
import sys
sys.path.insert(0, sys.argv[1])
import scan
def hits(terms, text):
    """The matched text of every private-term finding in TEXT (gitleaks' passes left out)."""
    with scan.Scanner(scan.Terms(terms, None)) as sc:
        sc._pass = lambda exe, cfg, n: []
        sc.add("demo", text)
        return [t for rule, _idx, _line, t in sc.findings() if rule == "private-term"]
CASES = []
def case(name, terms, text, want):
    CASES.append((name, terms, text, want))
A = ["acme"]
# T11. RED WHEN: a letter or digit that is not ASCII (here an accented letter or an Arabic-Indic
# digit) next to the term makes it part of a longer word: such a term is reported.
# (Changed: these cases were clean under the previous rule, which treated every cased letter or
# decimal digit as part of a word. A combining acute on the last letter moved to the word-edge cases below.)
case("T11: e-acute before the term", A, "\u00e9acme", ["acme"])
case("T11: e-acute after the term", A, "acme\u00e9", ["acme"])
case("T11: an Arabic-Indic digit before the term", A, "\u0663acme", ["acme"])
# T11 partner. RED WHEN: a mark on one of the term's own letters (not its last) no longer hides
# that spelling (only a term's last letter may carry marks).
case("T11 partner: a-acute in place of the term's a", A, "\u00e1cme", [])
case("T11 partner: a hyphen and an underscore are breaks", A, "x-acme_y", ["acme"])
case("T11 partner: two hits on one line", A, "acme acme", ["acme", "acme"])
# T11b. RED WHEN: the word test reads folded characters (a symbol can fold to letters), or
# characters other than ASCII letters and digits count as word characters.
for label, text, got in (("a trade mark sign", "Acme\u2122 Labs", "Acme"), ("a numero sign", "\u2116acme", "acme"),
                         ("a Han letter before", "\u793eacme", "acme"), ("a Han letter after", "acme\u793e", "acme"),
                         ("a Thai letter with a tone mark", "\u0e01\u0e48acme", "acme"),
                         ("Katakana with a length mark", "\u30b5\u30fc\u30d0\u30fcacme", "acme"),
                         ("Thai with a repetition mark", "\u0e14\u0e35\u0e46acme", "acme"),
                         ("an ideographic iteration mark", "acme\u3005", "acme"),
                         ("an ideographic zero", "\u3007acme", "acme")):
    case("T11b: the term next to %s is found" % label, A, text, [got])
# T11c. RED WHEN: units are folded one character at a time (NFC and NFD spellings then differ),
# or invisible characters are not removed first.
case("T11c: an NFC term is found in NFD text with its marks in another order",
     ["\u00e1\u0316"], "x a\u0316\u0301 y", ["a\u0316\u0301"])
case("T11c: a zero-width space inside the term", A, "ac\u200bme", ["ac\u200bme"])
case("T11c: a variation selector after the term", A, "acme\ufe0f", ["acme"])
# T12. RED WHEN: after a rejected hit the search restarts at its end instead of one past its start.
case("T12: a-a in xa-a-a is found once, at the second a-a", ["a-a"], "xa-a-a", ["a-a"])
case("T12 partner: terms a-b and b in xa-b find b", ["a-b", "b"], "xa-b", ["b"])
# T12b. RED WHEN: all terms share one alternation with the word test outside it (a shorter term
# that fails the word test then hides a longer one).
case("T12b: acme and acmecorp in 'see acmecorp.x' find acmecorp", ["acme", "acmecorp"], "see acmecorp.x", ["acmecorp"])
case("T12b: acme corp and acme in 'acme corpx' find acme", ["acme corp", "acme"], "acme corpx", ["acme"])
# T9b. RED WHEN: the special case for U+0130 and U+0131 is removed (Turkish capital I with a
# dot, and dotless i, then fold to something other than i).
case("T9b: a capital I with a dot", ["istanbul"], "\u0130STANBUL", ["\u0130STANBUL"])
case("T9b: a dotless i", ["istanbul"], "\u0131stanbul", ["\u0131stanbul"])
# T9c. RED WHEN: a term's words are joined with [-_. ]? (a term with two separators in a row
# then never matches itself).
case("T9c: a term with a full stop and a space between words", ["Acme Inc. Labs"], "made by Acme Inc. Labs today",
     ["Acme Inc. Labs"])
case("T9c partner: a term holding an ellipsis", ["a\u2026b"], "x a\u2026b y", ["a\u2026b"])
for name, terms, text, want in CASES:
    got = hits(terms, text)
    print(("ok " if got == want else "bad ") + name + ("" if got == want else " - got %s, want %s" % (ascii(got), ascii(want))))
EOF
py_verdicts "$TERMPY" "$ROOT/public-content"

UNITPY="$WORK/units.py"
cat >"$UNITPY" <<'EOF'
import os, random, re, subprocess, sys, tempfile, unicodedata
sys.path.insert(0, sys.argv[1])
import scan
def report(name, good, detail=""):
    print(("ok " if good else "bad ") + name + ("" if good else " - " + detail))
def found(terms, text):
    return [t for _n, t in scan.Terms(terms, None).find(text)]
def run_report(terms, add):
    """The report lines of a run over what ADD adds (gitleaks' passes left out)."""
    with scan.Scanner(scan.Terms(terms, None)) as sc:
        sc._pass = lambda exe, cfg, n: []
        add(sc)
        return sc.run()

# The fold of a line is whole-string Unicode compatibility caseless match (D146) plus one Turkish
# adjustment, with the invisible characters removed first: U+0131 (dotless i) is read as i, and a
# U+0307 (dot above) that follows an i with only combining characters between is dropped.
# Dropping it before or after canonical reordering gives the same text, since reordering only
# moves combining characters within their run.
# The invisible characters: every character of category Cf, and Unicode's
# Default_Ignorable_Code_Point (16.0, the same in 15.0), written here as hex ranges.
INVISIBLE = ((0xAD, 0xAD), (0x34F, 0x34F), (0x61C, 0x61C), (0x115F, 0x1160), (0x17B4, 0x17B5), (0x180B, 0x180F),
             (0x200B, 0x200F), (0x202A, 0x202E), (0x2060, 0x206F), (0x3164, 0x3164), (0xFE00, 0xFE0F),
             (0xFEFF, 0xFEFF), (0xFFA0, 0xFFA0), (0xFFF0, 0xFFF8), (0x1BCA0, 0x1BCA3), (0x1D173, 0x1D17A),
             (0xE0000, 0xE0FFF))
def invisible(c):
    return unicodedata.category(c) == "Cf" or any(a <= ord(c) <= b for a, b in INVISIBLE)
def strip(s):
    return "".join(c for c in s if not invisible(c))
T = scan.Terms(["x"], None)
def d146(s):
    s = strip(s)
    n = unicodedata.normalize
    s = n("NFKD", n("NFKD", n("NFD", s).casefold()).casefold()).replace("\u0131", "i")
    out = []
    for c in s:
        if c == "\u0307":
            k = len(out) - 1
            while k >= 0 and unicodedata.category(out[k])[0] == "M":
                k -= 1
            if k >= 0 and out[k] == "i":
                continue
        out.append(c)
    return "".join(out)
POOL = (list("abcinpxyzIK019 -_.") + [
    "\u00e9", "\u00c5", "\u0301", "\u0316", "\u0323", "\u0345", "\u0307", "\u031b", "\u0130", "\u0131",
    "\U0001d6a4", "\u212a", "\u017f", "\u00df", "\u1e9e", "\ufb00", "\ufb03", "\u0149", "\uff21", "\uff41",
    "\uff76", "\uff9e", "\u03d2", "\u03d3", "\u03c5", "\u03a5", "\u1f88", "\u1fb3", "\u0390", "\uac00",
    "\u1100", "\u1161", "\u304b", "\u3099", "\u30cf", "\u309a", "\u200b", "\ufe0f", "\u00ad", "\u034f",
    "\U000e0041", "\u2122", "\u00bd", "\u2460"])
rnd = random.Random(20261118)
bad = []
# The fold may write the iota an iota subscript (U+0345) folds to as one character of its own (the
# last character of the fold of alpha + U+0345); it is read back as iota here.
IOTA = T._line("\u03b1\u0345")[1][1:]
for _ in range(20000):
    s = "".join(rnd.choice(POOL) for _ in range(rnd.randint(0, 12)))
    units, folded, owner = T._line(s)
    if folded.replace(IOTA, "\u03b9") != d146(s) or len(owner) != len(folded) or "".join(units) != s \
            or any(not 0 <= k < len(units) for k in owner) or any(a > b for a, b in zip(owner, owner[1:])):
        bad.append(s)
# T16. RED WHEN: a fold step is left out (the first NFKD: U+1D6A4, a dotless i only NFKD
# reveals, then stays a dotless i; the second casefold; a canonical reordering pass), invisible
# characters are not removed before the fold, a dot above that follows an i and a mark is kept,
# or a folded character is owned by a unit other than its own (the owners then decrease).
# (Changed: the oracle removes the invisible characters by its own hex list, drops the
# dot above as described above, and owners must never decrease. The units still join to the line as
# written: an invisible character stays in the unit before it.)
# (Changed: the iota of an iota subscript is read back from the fold's own character for it.)
report("T16: 20 000 random lines fold to whole-string D146 with owners that never decrease", not bad,
       "%d lines differ, first %s" % (len(bad), ascii(bad[:3])))
# T16 partner. RED WHEN: the iota of an iota subscript is written as more than one character, or as
# a character the fold of another of the characters above gives, or a separator.
report("T16 partner: an iota subscript folds to one character, iota or one no other test character folds to",
       len(IOTA) == 1 and (IOTA == "\u03b9" or all(IOTA not in d146(c) for c in POOL)) and IOTA not in "-_. ",
       ascii(IOTA))
# T16 partner. RED WHEN: an NFKD pass or the dotless-i step is left out (the reported case: a
# mathematical dotless i inside a term).
report("T16: the term pin is found in p + U+1D6A4 + n", found(["pin"], "p\U0001d6a4n") == ["p\U0001d6a4n"],
       ascii(found(["pin"], "p\U0001d6a4n")))
# T16 partner. RED WHEN: the second casefold of D146 is left out (U+03D2 folds to upsilon only after NFKD).
report("T16: the term upsilon-x is found in U+03D2 + x", found(["\u03c5x"], "\u03d2x") == ["\u03d2x"],
       ascii(found(["\u03c5x"], "\u03d2x")))

# T17. RED WHEN: the pure-ASCII fast path gives a result the general path does not (it is the
# guard of that path: disabling the fast path changes nothing, so no other test can see it).
terms = ["ab", "a-b", "x.y", "B", "ab ab"]
diff = []
for _ in range(3000):
    s = "".join(rnd.choice("aAbB-_. xyXY1") for _ in range(rnd.randint(0, 24)))
    fast = scan.Terms(terms, None)
    slow = scan.Terms(terms, None)
    general = getattr(slow, "_general", None)
    if general is None:
        diff.append("no general path to compare")
        break
    slow._line = general
    a, b = fast._line(s), general(s)
    if (list(a[0]), a[1], list(a[2])) != (list(b[0]), b[1], list(b[2])) or fast.find(s) != slow.find(s) \
            or fast.mask(s) != slow.mask(s):
        diff.append(s)
report("T17: on 3 000 random ASCII lines the fast path equals the general path", not diff, ascii(diff[:3]))

# T18. RED WHEN: a term's separator allowance is not its own longest run of separators as
# written (a term with four in a row then never finds itself, and its file name shows unmasked).
report("T18: a term with four full stops in a row finds itself", found(["acme....labs"], "acme....labs") == ["acme....labs"],
       ascii(found(["acme....labs"], "acme....labs")))
report("T18 partner: the term with four full stops masks itself", scan.Terms(["acme....labs"], None).mask("acme....labs.txt")
       == "<private>.txt", scan.Terms(["acme....labs"], None).mask("acme....labs.txt"))
# T18 partner. RED WHEN: a term written with one separator allows more than one between its
# words, or its allowance is counted after folding (the term written with an ellipsis then
# allows three, and finds two spaces).
# (Changed: a term written with one separator was found across three; the owner's answer
# on separators allows one.)
for line, want in (("ab", ["ab"]), ("a_b", ["a_b"]), ("a-b", ["a-b"])):
    report("T18 partner: a term written with one hyphen is found with one or none (%s)" % line,
           found(["a-b"], line) == want, ascii(found(["a-b"], line)))
for line in ("a--b", "a---b", "a----b"):
    report("T18 partner: a term written with one hyphen is not found across %d" % (len(line) - 2),
           found(["a-b"], line) == [], ascii(found(["a-b"], line)))
report("T18 partner: a term written with one full stop is found across one ellipsis",
       found(["a.b"], "a\u2026b") == ["a\u2026b"], ascii(found(["a.b"], "a\u2026b")))
report("T18 partner: a term written with one ellipsis is not found across two spaces",
       found(["acme\u2026labs"], "acme  labs") == [], ascii(found(["acme\u2026labs"], "acme  labs")))
report("T18 partner: a term written with one ellipsis finds itself",
       len(found(["acme\u2026labs"], "acme\u2026labs")) == 1, ascii(found(["acme\u2026labs"], "acme\u2026labs")))

# T19. RED WHEN: load_terms stops checking that every term finds its own text, or its error
# names the term instead of the line number.
notes = tempfile.mkdtemp()
os.makedirs(os.path.join(notes, "scanner"))
with open(os.path.join(notes, "scanner", "private-terms.txt"), "w", encoding="utf-8") as f:
    f.write("# a comment\nacme\nqqhiddenterm\n")
os.environ["PRIVATE_NOTES_DIR"] = notes
scan._recorded_notes_dir = lambda: None
real_find = scan.Terms.find
scan.Terms.find = lambda self, text: [] if text == "qqhiddenterm" else real_find(self, text)
try:
    scan.load_terms()
    report("T19: a term that does not find itself fails the load, naming its line", False, "no error")
except scan.ScanError as exc:
    report("T19: a term that does not find itself fails the load, naming its line",
           "line 3" in str(exc) and "qqhidden" not in str(exc), str(exc).replace("qqhidden", "<term>"))
finally:
    scan.Terms.find = real_find
# T19 partner. RED WHEN: the check rejects a term that does find itself.
try:
    report("T19 partner: a list whose terms find themselves loads", len(scan.load_terms().patterns) == 2)
except scan.ScanError as exc:
    report("T19 partner: a list whose terms find themselves loads", False, str(exc))

def load_error(lines):
    """The ScanError text of load_terms over a list holding LINES, or None when it loads."""
    with open(os.path.join(notes, "scanner", "private-terms.txt"), "w", encoding="utf-8") as f:
        f.write(lines)
    try:
        scan.load_terms()
        return None
    except scan.ScanError as exc:
        return str(exc)
# T24. RED WHEN: load_terms checks only the terms that yield a pattern (a term of separators
# alone yields none, so it would load and match nothing), or the error names the term.
got = load_error("acme\n....\n")
report("T24: a term with no letters or digits fails the load, naming its line",
       got is not None and "line 2" in got and "...." not in got, ascii(got))
# T24 partner. RED WHEN: a term may start with a combining mark (its first unit has no base).
got = load_error("acme\n# note\n\u0301acme\n")
report("T24: a term that starts with a combining mark fails the load, naming its line",
       got is not None and "line 3" in got and "acme" not in got, ascii(got))
got = load_error("acme\n\u200d\u0323x\n")
report("T24: a term whose first unit after an ignorable one has no base fails the load",
       got is not None and "line 2" in got, ascii(got))
# T24 partner. RED WHEN: the check rejects a term holding a mark after its first letter.
got = load_error("acme\nacm\u00e9 labs\nx\u0301y\n")
report("T24 partner: terms with a base letter first load", got is None, ascii(got))
# Load check. RED WHEN: the load check tests only category M, not the first folded character: a term
# whose first visible character attaches to the character before it (U+FF9E and U+FF9F, the
# half-width sound marks, fold to combining marks; so do the Thai and Lao sara am) loads and can
# never be found after a space. Or the one check stops covering category M (U+0903 is Mc with
# combining class 0).
for label, first in (("U+0903", "\u0903"), ("U+FF9E", "\uff9e"), ("U+FF9F", "\uff9f"), ("U+0E33", "\u0e33"),
                     ("U+0EB3", "\u0eb3"), ("a zero-width space, then U+FF9E", "\u200b\uff9e")):
    got = load_error("acme\n" + first + "acme\n")
    report("Load check: a term whose first visible character is attached (%s) fails the load, naming its line" % label,
           got is not None and "line 2" in got and "acme" not in got, ascii(got))
# Load check partner. RED WHEN: the check rejects a term whose attached characters follow a base.
got = load_error("acme\nx\uff9eacme\nacme\u0e33\n")
report("Load check partner: terms with attached characters after a base load", got is None, ascii(got))

# T20. RED WHEN: a unit is grown one character at a time (each mark copies the unit so far:
# quadratic in a run of marks). Run in a child process so a quadratic build cannot hang the suite.
code = ("import sys, time; sys.path.insert(0, sys.argv[1]); import scan; t = scan.Terms(['acme'], None); "
        "line = 'a' + '\\u0301' * 1000000; t0 = time.time(); "
        "ok = t.find(line) == [] and t.mask(line) == line; print('%s %.2f' % (ok, time.time() - t0))")
try:
    r = subprocess.run([sys.executable, "-I", "-B", "-c", code, sys.argv[1]], capture_output=True, text=True, timeout=30)
    got = r.stdout.split()
    report("T20: one letter and 1 000 000 marks are found and masked in under 2 s",
           r.returncode == 0 and got[0] == "True" and float(got[1]) < 2, (r.stdout + r.stderr)[-200:])
except subprocess.TimeoutExpired:
    report("T20: one letter and 1 000 000 marks are found and masked in under 2 s", False, "over 30 s")

# T21. RED WHEN: the word test stops skipping ignorable characters on the left (M13) or on the
# right (M19): a zero-width space between the term and a letter then hides the letter.
report("T21: a letter, a zero-width space, then the term is clean", found(["acme"], "x\u200bacme") == [],
       ascii(found(["acme"], "x\u200bacme")))
report("T21: the term, a zero-width space, then a letter is clean", found(["acme"], "acme\u200bx") == [],
       ascii(found(["acme"], "acme\u200bx")))
# T21 partner. RED WHEN: a hit may start inside a unit (the ff ligature folds to two letters, the
# second of which starts the term's folded text).
report("T21: the term fabc is not found inside the ff ligature + abc", found(["fabc"], "\ufb00abc") == [],
       ascii(found(["fabc"], "\ufb00abc")))
report("T21 partner: the term ffabc is found in the ff ligature + abc", found(["ffabc"], "\ufb00abc") == ["\ufb00abc"],
       ascii(found(["ffabc"], "\ufb00abc")))

# T22. RED WHEN: the report's duplicate test is removed (M16): two hits on one line print twice.
got = run_report(["acme"], lambda sc: sc.add("demo", "acme acme\n"))
report("T22: two hits of one term on one line print one report line", got == ["private-term at demo:1"], ascii(got))
# T23. RED WHEN: the withhold test goes back to `text in mask(name)` (M17): the matched text ate
# occurs inside <private>, so a name that masking made safe is withheld instead of shown masked.
got = run_report(["ate"], lambda sc: sc.add_names("a file name", ["ate-notes.txt"]))
report("T23: a name holding only a term and plain text is shown masked",
       got == ["private-term at the file name <private>-notes.txt"], ascii(got))
got = run_report(["acme"], lambda sc: sc.add_names("a file name", ["acme-notes.txt"]))
report("T23 partner: acme-notes.txt is shown masked", got == ["private-term at the file name <private>-notes.txt"], ascii(got))

# T25. RED WHEN: a hit may not end inside its last unit where the rest of that unit is combining
# characters: written as accents after the letter, or produced by decomposing a
# precomposed letter, also once the CGJ (an invisible character) between them is removed; or
# invisible characters are removed after the unit split, so the CGJ splits the marks.
# (Changed: both cases were clean. The owner's answers report a term whose last letter
# carries a combining accent, in either storage form.)
for label, line in (("acm + e-acute + CGJ + grave below", "acm\u00e9\u034f\u0316"),
                    ("acm + e + acute + CGJ + grave below", "acme\u0301\u034f\u0316")):
    report("T25: the term acme is found in %s" % label, len(found(["acme"], line)) == 1, ascii(found(["acme"], line)))
# T25 partner. RED WHEN: a hit may not end just before the marks written after its last letter,
# or an ASCII letter after those marks no longer makes the hit part of a longer word.
report("T25 partner: acme + CGJ + grave below finds acme", len(found(["acme"], "acme\u034f\u0316")) == 1,
       ascii(found(["acme"], "acme\u034f\u0316")))
report("T25 partner: acme + acute + x is clean", found(["acme"], "acme\u0301x") == [],
       ascii(found(["acme"], "acme\u0301x")))
# T26. Case 1 RED WHEN: invisible characters are removed after the units are split (the
# zero-width joiner then parts the e-acute from its dot below, and the term is not found), or a
# hit is not mapped back to the original text with the invisible character inside it (find then
# returns too little, and mask leaves part showing).
# Case 2 builds Terms directly (a term of marks alone fails the load). RED WHEN: find accepts a
# hit that starts inside a unit (the marks of a letter then match alone).
for label, term, line, want_find in (
        ("e with dot below and acute, in e-acute + ZWJ + dot below", "\u1eb9\u0301",
         "\u00e9\u200d\u0323", ["\u00e9\u200d\u0323"]),
        ("dot below and acute, in a-acute + ZWJ + dot below", "\u0323\u0301",
         "\u00e1\u200d\u0323", [])):
    t = scan.Terms([term], None)
    got_find, got_mask = [x for _n, x in t.find(line)], t.mask(line)
    report("T26: %s finds %s and masks every matched unit" % (label, ascii(want_find)),
           got_find == want_find and got_mask == "<private>", ascii((got_find, got_mask)))
# T27. RED WHEN: the segment cache grows without bound (each distinct short segment of a line
# stays in it, so a long run of distinct text holds memory for the life of the Terms).
limit = getattr(scan.Terms, "SEGMENT_CACHE_LIMIT", None)
t = scan.Terms(["acme"], None)
t.find("".join(chr(0x20000 + i) for i in range(40000)))
report("T27: 40 000 distinct segments leave the segment cache at or under its bound",
       isinstance(limit, int) and 0 < limit <= 10000 and len(t._segments) <= limit,
       "limit %r, %d entries" % (limit, len(t._segments)))
# T27 partner. RED WHEN: the cache is never filled (the bound then holds trivially).
t = scan.Terms(["acme"], None)
t.find("x\u00e9y")
report("T27 partner: a short non-ASCII line fills the segment cache", len(t._segments) > 0, str(len(t._segments)))
# T20 partner. RED WHEN: a long run of marks of different classes is sorted or matched in more
# than linear-log time. Run in a child process so a slow path cannot hang the suite.
code = ("import sys, time; sys.path.insert(0, sys.argv[1]); import scan; t = scan.Terms(['acme'], None); "
        "line = 'a' + '\\u0301\\u0323\\u0345' * 333334; t0 = time.time(); "
        "ok = t.find(line) == [] and t.mask(line) == line; print('%s %.2f %d' % (ok, time.time() - t0, len(line)))")
try:
    r = subprocess.run([sys.executable, "-I", "-B", "-c", code, sys.argv[1]], capture_output=True, text=True, timeout=60)
    got = r.stdout.split()
    report("T20 partner: one letter and 1 000 000 marks of three classes are found and masked in under 10 s",
           r.returncode == 0 and got[0] == "True" and float(got[1]) < 10 and int(got[2]) > 1000000,
           (r.stdout + r.stderr)[-200:])
except subprocess.TimeoutExpired:
    report("T20 partner: one letter and 1 000 000 marks of three classes are found and masked in under 10 s",
           False, "over 60 s")
EOF
py_verdicts "$UNITPY" "$ROOT/public-content"

echo "== (m) private terms: invisible characters, attached characters, word edges, separators"
# Every character below is written as an escape, so this file holds no invisible or combining
# character. All terms are made-up words.
R11PY="$WORK/r11terms.py"
cat >"$R11PY" <<'EOF'
import random, sys, unicodedata
sys.path.insert(0, sys.argv[1])
import scan
SRC = sys.argv[2]
def report(name, good, detail=""):
    print(("ok " if good else "bad ") + name + ("" if good else " - " + detail))
BUILT = {}
def built(terms):
    if tuple(terms) not in BUILT:
        BUILT[tuple(terms)] = scan.Terms(terms, None)
    return BUILT[tuple(terms)]
def found(terms, text):
    return [t for _n, t in built(terms).find(text)]
def count(terms, text):
    return len(built(terms).find(text))
nfc = lambda s: unicodedata.normalize("NFC", s)
nfd = lambda s: unicodedata.normalize("NFD", s)
fold = lambda s: unicodedata.normalize("NFKD", unicodedata.normalize("NFKD", nfd(s).casefold()).casefold())
INVISIBLE = ((0xAD, 0xAD), (0x34F, 0x34F), (0x61C, 0x61C), (0x115F, 0x1160), (0x17B4, 0x17B5), (0x180B, 0x180F),
             (0x200B, 0x200F), (0x202A, 0x202E), (0x2060, 0x206F), (0x3164, 0x3164), (0xFE00, 0xFE0F),
             (0xFEFF, 0xFEFF), (0xFFA0, 0xFFA0), (0xFFF0, 0xFFF8), (0x1BCA0, 0x1BCA3), (0x1D173, 0x1D17A),
             (0xE0000, 0xE0FFF))
def invisible(c):
    return unicodedata.category(c) == "Cf" or any(a <= ord(c) <= b for a, b in INVISIBLE)
def strip(s):
    return "".join(c for c in s if not invisible(c))
def chars():
    return (chr(cp) for cp in range(0x110000) if not 0xD800 <= cp <= 0xDFFF)
A = ["acme"]

# Word edges and storage forms. RED WHEN: a letter or digit that is not ASCII, a combining character, or a character
# attached to the last letter (U+FF9E, the Thai sara am) next to a hit makes it part of a longer
# word; or the two storage forms of one text (precomposed, or letter + combining accent) give
# different results. Each text is also checked in NFC and in NFD.
for label, texts in (
        ("a grave below after the last letter", ["acme\u0316"]),
        ("an accented last letter", ["acm\u00e9", "acme\u0301", "acm\u1ec7"]),
        ("an accented letter after the term", ["acme\u00e9", "acmee\u0301"]),
        ("an accented letter before the term", ["\u00e9acme", "e\u0301acme"]),
        ("a Greek letter after the term", ["acme\u03a9", "acme\u03ac", "acme\u03b1\u0301"]),
        ("a Cyrillic letter after the term", ["acme\u0434", "acme\u0439", "acme\u0438\u0306"]),
        ("an Arabic-Indic digit before the term", ["\u0663acme"]),
        ("a half-width sound mark after the term", ["acme\uff9e"]),
        ("Katakana before and a half-width sound mark after", ["\u30a2acme\uff9e"]),
        ("the Thai sara am after the term", ["acme\u0e33"]),
        ("a Greek ypogegrammeni after the term", ["acme\u0345"]),
        ("marks on both sides of a CGJ after the last letter", ["acme\u0301\u034f\u0316", "acm\u00e9\u034f\u0316"])):
    for text in texts:
        got = [count(A, t) for t in (text, nfc(text), nfd(text))]
        report("Word edges: the term is found next to %s (%s), in both storage forms" % (label, ascii(text)),
               got == [1, 1, 1], "counts %s for the text, NFC, NFD" % got)
# Turkish i. RED WHEN: the Turkish rule drops a dot above only when it directly follows an i (an
# attached grave below then keeps the dot, and the spellings of one word differ), or an invisible
# character between them acts as an edge.
for spelling in ("ali", "al\u0130", "alI\u0307", "al\u0131", "al\u0131\u0307"):
    for suffix in ("", "\u200d", "\u0316", "\u200d\u0316", "\u0316\u0307"):
        report("Turkish i: the term ali is found in %s" % ascii(spelling + suffix), count(["ali"], spelling + suffix) == 1,
               ascii(found(["ali"], spelling + suffix)))
# Word edges partners. RED WHEN: an ASCII letter or digit next to a hit, with or without marks on it, no
# longer makes the hit part of a longer word (also after the marks that end the hit, or across
# an invisible character).
for text in ("acmex", "xacme", "acme1", "1acme", "acme\u0301x", "acm\u00e9x", "x\u0301acme", "acmex\u0301",
             "acme\uff9ex", "acme\u0e33x", "acme\u200bx", "acme\u034fx", "x\u200dacme", "acme\u0301\u200d1"):
    got = [count(A, t) for t in (text, nfc(text), nfd(text))]
    report("Word edges partner: the term is clean in %s, in both storage forms" % ascii(text), got == [0, 0, 0],
           "counts %s for the text, NFC, NFD" % got)
# Hit ends. RED WHEN: a hit may end inside a letter's own fold (the term s in a sharp
# s, f in the ff ligature), or a hit no longer needs the rest of its last unit to be combining
# characters only.
for terms, text, want in ((["s"], "\u00df", 0), (["ss"], "\u00df", 1), (["f"], "\ufb00", 0), (["ff"], "\ufb00", 1),
                          (["acm"], "acme", 0), (["acm"], "acm\u00e9", 1), (["acme"], "acm\u00e9x", 0)):
    report("Hit ends: %s in %s gives %d" % (ascii(terms[0]), ascii(text), want), count(terms, text) == want,
           ascii(found(terms, text)))

# Separators. RED WHEN: separators in a line are counted after folding (an ellipsis or a two-dot leader
# then counts as two or three), a term written with one separator allows more than one, or an
# invisible character between two separators keeps them apart.
L = ["acme labs"]
for text in ("acme labs", "acme-labs", "acmelabs", "acme_labs", "acme.labs", "acme\u2026labs", "acme\u2025labs",
             "acme\u3000labs", "acme\u00a0labs", "acme\u200b labs"):
    report("Separators: acme labs is found in %s" % ascii(text), count(L, text) == 1, ascii(found(L, text)))
for text in ("acme. labs", "acme  labs", "acme \u200b labs", "acme--labs", "acme\u2026 labs", "acme\u2026\u2026labs"):
    report("Separators: acme labs is not found in %s" % ascii(text), count(L, text) == 0, ascii(found(L, text)))
# Term separators. RED WHEN: a term's own allowance is counted after folding (a term written with one
# ellipsis then allows three; one with two ellipses allows six), or is not its own longest run
# of separators as written, mixed runs included.
for term, text, want in (("acme\u2026labs", "acme  labs", 0), ("acme\u2026labs", "acme\u2026labs", 1),
                         ("acme\u2026labs", "acme labs", 1), ("a\u2026\u2026b", "a..b", 1),
                         ("a\u2026\u2026b", "a...b", 0), ("acme. labs", "acme -labs", 1),
                         ("acme. labs", "acme. labs", 1), ("acme. labs", "acme.  labs", 0),
                         ("acme -labs", "acme. labs", 1), ("acme -labs", "acme labs", 1)):
    report("Term separators: the term %s in %s gives %d" % (ascii(term), ascii(text), want), count([term], text) == want,
           ascii(found([term], text)))

# Format characters (fail closed). RED WHEN: a character of category Cf, or of
# Default_Ignorable_Code_Point, is kept inside a term instead of removed (it then splits the term
# and hides it).
kept = [hex(ord(c)) for c in chars() if invisible(c) and count(A, "ac" + c + "me") != 1]
report("Format characters: every invisible character inside the term is removed (%d code points)"
       % sum(1 for c in chars() if invisible(c)), not kept, "kept: %s" % kept[:10])
every_cf = [c for c in chars() if unicodedata.category(c) == "Cf"]
kept = [hex(ord(c)) for c in every_cf if count(A, "ac" + c + "me") != 1]
report("Format characters: each of the %d characters of category Cf inside the term keeps it found" % len(every_cf),
       len(every_cf) >= 160 and not kept, "kept: %s" % kept[:10])
# Format characters partner. RED WHEN: visible characters are removed too (a visible letter inside the term
# then no longer keeps it apart).
for c in ("x", "\u00e9", "\u0600x"):
    report("Format characters partner: %s inside the term keeps it apart" % ascii(c), count(A, "ac" + c + "me") == 0,
           ascii(found(A, "ac" + c + "me")))
# Format characters partner. RED WHEN: a removed format character still acts as a break (x then U+0600 then the
# term must read as xacme, part of a longer word).
report("Format characters partner: x + U+0600 + the term is clean", count(A, "x\u0600acme") == 0, ascii(found(A, "x\u0600acme")))

# Kelvin sign. RED WHEN: the word test reads a neighbouring Kelvin sign (U+212A) as it is written, not
# as the letter K its NFC form is: it is an ASCII letter after the term, so the term is part of
# a longer word.
for text in ("acme\u212a", "\u212aacme"):
    report("Kelvin sign: the term next to a Kelvin sign is clean (%s)" % ascii(text), count(A, text) == 0, ascii(found(A, text)))

# Attached characters. RED WHEN: Unicode data changes the attached characters that are not marks (the
# test then names the new set), or an attached character is not read as part of the unit before
# it: after an ASCII letter it then becomes a break before the term, and after the term's last
# letter it no longer ends the hit. Attached = category M, or a first folded character of category M.
attached = [c for c in chars() if not invisible(c) and (unicodedata.category(c)[0] == "M"
            or (fold(c) and unicodedata.category(fold(c)[0])[0] == "M"))]
not_marks = sorted(hex(ord(c)) for c in attached if unicodedata.category(c)[0] != "M")
report("Attached characters: the attached characters that are not marks are U+0E33, U+0EB3, U+FF9E and U+FF9F",
       not_marks == ["0xe33", "0xeb3", "0xff9e", "0xff9f"], str(not_marks))
after_x = [c for c in attached if nfc("x" + c)[0] == "x"]
left = [hex(ord(c)) for c in after_x if count(A, "x" + c + "acme") != 0]
report("Attached characters: x + each of %d attached characters before the term keeps it part of a word" % len(after_x),
       len(after_x) > 2000 and not left, "found after: %s" % left[:10])
right = [hex(ord(c)) for c in attached if count(A, "acme" + c) != 1]
report("Attached characters: the term is found before each of %d attached characters" % len(attached),
       len(attached) > 2000 and not right, "not found before: %s" % right[:10])

# Invisible characters. RED WHEN: an invisible character changes a result: it acts as a unit edge, splits a
# separator run, is removed after the units are split, or is left out of the original text a
# hit maps back to. Each line gives the same findings (invisible characters left out) and the
# same mask with and without them.
POOL = list("acmelbis x1-_.") + ["\u00e9", "\u0301", "\u0316", "\u0130", "\u0131", "\u0307", "\u00df", "\ufb00",
                                 "\uff9e", "\u0e33", "\u03a9", "\u0434", "\u2026", "\u3000", "\u0600", "\u0345",
                                 "\u200b", "\u200d", "\u034f", "\u00ad", "\ufe0f", "\U000e0041", "\u2060", "\u180e"]
terms = scan.Terms(["acme", "acme labs", "ali", "s", "ab", "m-e"], None)
rnd = random.Random(20261119)
diff = []
for _ in range(20000):
    s = "".join(rnd.choice(POOL) for _ in range(rnd.randint(0, 14)))
    a = [(n, strip(t)) for n, t in terms.find(s)]
    b = [(n, strip(t)) for n, t in terms.find(strip(s))]
    if a != b or strip(terms.mask(s)) != terms.mask(strip(s)):
        diff.append(s)
report("Invisible characters: 20 000 random lines give the same findings and mask with and without invisible characters", not diff,
       "%d lines differ, first %s" % (len(diff), ascii(diff[:3])))

# Greek iota subscript. RED WHEN: the letters of a unit are counted on its fold instead of on
# its canonical decomposition with the marks removed: a precomposed letter with an iota subscript
# (U+1F80-U+1FFC) then hides a Greek term ending in its base letter, while the same text written
# as letter + U+0345 is found. Checked for every such code point, in both storage forms.
iota = [c for c in chars() if "\u0345" in nfd(c) and len(nfd(c)) > 1 and unicodedata.category(nfd(c)[0])[0] == "L"]
split = []
for c in iota:
    base = "".join(x for x in nfd(c) if unicodedata.category(x)[0] != "M")
    term = ["\u03b2" + base]
    got = [count(term, "\u03b2" + c), count(term, "\u03b2" + nfd(c))]
    if got != [1, 1]:
        split.append((hex(ord(c)), got))
report("Greek iota subscript: each of %d letters with an iota subscript ends a Greek term in both forms" % len(iota),
       len(iota) >= 60 and not split, "not found in both forms: %s" % split[:6])
for text in ("\u03b2\u1fb3 x", "\u03b2\u03b1\u0345 y"):
    report("Greek iota subscript: the term beta-alpha is found in %s" % ascii(text), count(["\u03b2\u03b1"], text) == 1,
           ascii(found(["\u03b2\u03b1"], text)))
# Greek iota subscript partner. RED WHEN: an ASCII letter after the letter with an iota subscript
# no longer makes the hit part of a longer word.
for text in ("\u03b2\u1fb3x", "\u03b2\u03b1\u0345x"):
    report("Greek iota subscript partner: the term beta-alpha is clean in %s" % ascii(text),
           count(["\u03b2\u03b1"], text) == 0, ascii(found(["\u03b2\u03b1"], text)))

# Accent then a lower mark. RED WHEN: a mark of a lower combining class after a term's accented
# last letter (U+0316, U+0323, U+0327, U+0E48, U+FF9E) is put between the letter and the term's own
# accent by canonical reordering, so the term's folded text no longer matches: find misses it and
# mask leaves it showing. Each case in both storage forms of the term and of the text.
for term in ("caf\u00e9", "cafe\u0301"):
    for follower in ("\u0316", "\u0323", "\u0327", "\u0e48", "\uff9e"):
        for text in ("caf\u00e9" + follower, "cafe\u0301" + follower):
            report("Accent then a lower mark: %s is found and masked in %s" % (ascii(term), ascii(text)),
                   count([term], text) == 1 and built([term]).mask(text) == "<private>",
                   "find %s, mask %s" % (ascii(found([term], text)), ascii(built([term]).mask(text))))
            # Partner. RED WHEN: an ASCII letter after those marks no longer makes the hit part of a longer word.
            report("Accent then a lower mark partner: %s is clean in %s" % (ascii(term), ascii(text + "x")),
                   count([term], text + "x") == 0, ascii(found([term], text + "x")))

# Hangul storage forms. RED WHEN: units are cut on the precomposed syllable instead of on its
# canonical decomposition (conjoining jamo): a term that starts or ends inside a syllable then gets
# a different answer for the syllable and for its jamo spelling. The sharp s and ff-ligature
# cases above stay clean (compatibility, not canonical, decompositions).
for term, pre in (("\u1100", "\uac00"), ("\u1161", "\uac00"), ("\uac00\u1100", "\uac00\uac00"),
                  ("\u1161\uac00", "\uac00\uac00"), ("\u1100\u1161", "\uac01"), ("\u11a8", "\uac01")):
    got = [count([term], pre), count([term], nfd(pre))]
    report("Hangul storage forms: the term %s is found in %s and in its jamo spelling" % (ascii(term), ascii(pre)),
           got == [1, 1], "counts %s for the syllables, the jamo" % got)
for terms, text in ((["s"], "\u00df"), (["f"], "\ufb00")):
    report("Hangul storage forms partner: %s stays clean in %s" % (ascii(terms[0]), ascii(text)),
           count(terms, text) == 0, ascii(found(terms, text)))

# Every character is written as an escape. U+1FB3 is alpha with an iota subscript (U+0345); its
# canonical decomposition is alpha + U+0345, and U+0345 folds to iota (U+03B9).
SUB = ("\u03b2\u1fb3", "\u03b2\u03b1\u0345")  # beta + alpha with an iota subscript, in both storage forms
FOLLOWERS = (("an acute", "\u0301"), ("a grave below", "\u0316"), ("a cedilla", "\u0327"), ("a Thai tone mark", "\u0e48"),
             ("a perispomeni", "\u0342"), ("a zero-width joiner then an acute", "\u200d\u0301"))
# Iota subscript then a mark. RED WHEN: a mark of a lower combining class than the iota subscript
# (230 and below; 240 for U+0345) after a term's last letter with an iota subscript is put before
# the iota by canonical reordering and the term's folded text no longer matches: find misses it
# and mask leaves it showing. Each case in both storage forms of the term and of the text, and in
# NFC and NFD.
for term in SUB:
    for label, follower in FOLLOWERS:
        bad = []
        for written in SUB:
            for text in {written + follower, nfc(written + follower), nfd(written + follower)}:
                if count([term], "x " + text + " y") != 1 or built([term]).mask(text) != "<private>":
                    bad.append((ascii(text), ascii(found([term], "x " + text + " y")), ascii(built([term]).mask(text))))
        report("Iota subscript then a mark: %s is found and masked with %s after it" % (ascii(term), label), not bad, str(bad[:2]))
# Iota subscript then a mark, partner. RED WHEN: an ASCII letter after those marks no longer makes
# the hit part of a longer word.
for term in SUB:
    for label, follower in FOLLOWERS:
        texts = [w + follower + "x" for w in SUB]
        got = [count([term], t) for t in texts]
        report("Iota subscript then a mark, partner: %s is clean with %s and a letter after it" % (ascii(term), label),
               got == [0, 0], str(got))
# Iota subscript, invisible characters. RED WHEN: an invisible character (a zero-width joiner or
# non-joiner, a combining grapheme joiner) between the letter with the iota subscript and the mark
# after it changes the result, in the term or in the text.
for inv in ("\u200d", "\u034f", "\u200c"):
    for term_inv in (False, True):
        bad = []
        for term in SUB:
            t = term + (inv + "\u0301" if term_inv else "")
            for written in SUB:
                for text in (written + inv + "\u0301", written + "\u0301"):
                    if count([t], "x " + text + " y") != 1 or built([t]).mask(text) != "<private>":
                        bad.append((ascii(t), ascii(text)))
        report("Iota subscript, invisible characters: U+%04X %s keeps the term found and masked"
               % (ord(inv), "in the term and the text" if term_inv else "in the text"), not bad, str(bad[:3]))
# Iota written plainly. RED WHEN: a plain iota in a term stops matching an iota subscript in the
# text (or the other way round): a term written with a plain iota is found and masked where the
# text has the letter with an iota subscript, in both storage forms, with or without a mark after it.
plain = "\u03b2\u03b1\u03b9"
for text in SUB + tuple(w + "\u0301" for w in SUB):
    report("Iota written plainly: %s is found and masked in %s" % (ascii(plain), ascii(text)),
           count([plain], "x " + text + " y") == 1 and built([plain]).mask(text) == "<private>",
           "find %s, mask %s" % (ascii(found([plain], "x " + text + " y")), ascii(built([plain]).mask(text))))
for term in SUB:
    report("Iota written plainly: %s is found and masked in %s" % (ascii(term), ascii(plain)),
           count([term], "x " + plain + " y") == 1 and built([term]).mask(plain) == "<private>",
           ascii(found([term], "x " + plain + " y")))
# Iota written plainly, partner. RED WHEN: marks are allowed before a plain iota in the text: an
# acute then a plain iota is a different spelling (alpha with an acute, then a separate iota),
# not an iota subscript, so the term with an iota subscript is clean there.
for term in SUB + (plain,):
    text = "\u03b2\u03b1\u0301\u03b9"
    report("Iota written plainly, partner: %s is clean in %s" % (ascii(term), ascii(text)),
           count([term], "x " + text + " y") == 0, ascii(found([term], "x " + text + " y")))
# Literal characters a fold could use inside. RED WHEN: a term or a text holding U+1FBE (prosgegrammeni,
# which decomposes to a plain iota) or the noncharacter U+FDD0 is read as something it is not:
# U+1FBE acts as a plain iota; U+FDD0 matches only itself.
pros = "\u03b2\u03b1\u1fbe"
for text in SUB + (plain, SUB[0] + "\u0301"):
    report("Literal characters: %s is found in %s" % (ascii(pros), ascii(text)), count([pros], "x " + text + " y") == 1,
           ascii(found([pros], "x " + text + " y")))
nonchar = "\u03b2\u03b1\ufdd0"
report("Literal characters: %s is found in itself" % ascii(nonchar),
       count([nonchar], "x " + nonchar + " y") == 1 and built([nonchar]).mask(nonchar) == "<private>",
       ascii(found([nonchar], "x " + nonchar + " y")))
for text in SUB + (plain, SUB[0] + "\u0301"):
    report("Literal characters partner: %s is clean in %s" % (ascii(nonchar), ascii(text)),
           count([nonchar], "x " + text + " y") == 0, ascii(found([nonchar], "x " + text + " y")))
for term in SUB + (plain,):
    text = "\u03b2\u03b1\ufdd0"
    report("Literal characters partner: %s is clean in %s" % (ascii(term), ascii(text)),
           count([term], "x " + text + " y") == 0, ascii(found([term], "x " + text + " y")))
# Iota subscript, first use. RED WHEN: the table of marks of each combining class is read before it
# is built: in a fresh process where the only term ends in a letter with an iota subscript (no other
# combining character in any term), an acute after it then hides the term or raises an error.
code = ("import sys; sys.path.insert(0, sys.argv[1]); import scan; "
        "t = scan.Terms(['\\u03b6\\u1fb3'], None); "
        "print(len(t.find('x \\u03b6\\u1fb3\\u0301 y')), t.mask('\\u03b6\\u1fb3\\u0301'))")
import subprocess
r = subprocess.run([sys.executable, "-I", "-B", "-c", code, sys.argv[1]], capture_output=True, text=True)
report("Iota subscript, first use: in a fresh process zeta + alpha with an iota subscript is found and masked with an acute after it",
       r.returncode == 0 and r.stdout.strip() == "1 <private>", "exit %d: %s %s" % (r.returncode, r.stdout.strip(), r.stderr.strip()[-200:]))

# Same fold, same result. RED WHEN: two terms that fold the same (Unicode's compatibility caseless
# match, D146) and allow the same separators give different results on a text: the iota subscript,
# a plain iota and their storage forms are spellings of one term. Random terms and texts, seeded.
def d146_stripped(s):
    n = unicodedata.normalize
    s = strip(s)
    return n("NFKD", n("NFKD", n("NFD", s).casefold()).casefold())
pool = [chr(c) for c in range(0x1F80, 0x1FFD) if "\u0345" in nfd(chr(c))] + list(
    "\u0323\u0316\u0301\u0300\u0342\u0313\u0314\u0308\u0345\u034f\u200d\u200c\u00df\u03b9\u0399\u1fbe\u037a"
    "\u03b1\u03b2\u03b6\u03c9\u0390\u03b0\u0e48\u0327abcz -")
foll = ["", "\u0301", "\u0316", "\u0e48", "\u200d\u0301", "x", "\u0345", "\u03b9", "\u0301\u0345"]
rnd = random.Random(20261120)
def variants(t):
    return {t, nfc(t), nfd(t), t.upper(), t.lower(), t.replace("\u03b9", "\u0345"), t.replace("\u0345", "\u03b9"),
            nfd(t).replace("\u0345", "\u03b9"), nfc(t.replace("\u03b9", "\u0345"))}
differ, groups, pairs = [], 0, 0
for _ in range(1500):
    t = "".join(rnd.choice(pool) for _ in range(rnd.randint(1, 6)))
    f0 = d146_stripped(t)
    group = []
    for v in sorted(variants(t)):
        tv = built([v])
        if v.strip() and d146_stripped(v) == f0 and tv.patterns:
            group.append(v)
    by_allow = {}
    for v in group:
        by_allow.setdefault(tuple(built([v])._most), []).append(v)
    for same in by_allow.values():
        if len(same) < 2:
            continue
        groups += 1
        texts = [" " + form(x + fl) + " end" for x in same for fl in foll for form in (nfc, nfd)]
        texts.append(" " + "".join(rnd.choice(pool) for _ in range(8)) + " ")
        for text in texts:
            got = {(bool(built([v]).find(text)), "<private>" in built([v]).mask(text)) for v in same}
            pairs += len(same)
            if len(got) > 1 and len(differ) < 5:
                differ.append((ascii(same), ascii(text)))
            elif len(got) > 1:
                differ.append(None)
report("Same fold, same result: %d groups of terms that fold the same give one result on every text" % groups,
       groups >= 200 and not differ, "%d texts differ, first %s" % (len(differ), differ[:3]))

# Escapes only. RED WHEN: a literal invisible or combining character (or any non-ASCII character other than
# the right single quote U+2019 of one reported-speech pattern) is written into scan.py: write
# escapes instead, so a reader sees every character.
with open(SRC, encoding="utf-8") as f:
    got = sorted({hex(ord(c)) for c in f.read() if ord(c) > 127})
report("Escapes only: the only non-ASCII character of scan.py is U+2019", got == ["0x2019"], str(got))
EOF
py_verdicts "$R11PY" "$ROOT/public-content" "$SCAN"

printf '%s\n%s\n' "$(_u '\u00df one\n\ufb00 two')" "we build $PTERM next" >"$WORK/t13.txt"
_text "$WORK/t13.txt"
# T13. RED WHEN: lines are counted in a folded string with a wrong index map (a sharp s and an ff
# ligature each fold to two characters).
expect_rc "T13: a term on line 3 after two lines that fold longer is reported on line 3" 1 "private-term at demo:3" @scanned
"$REAL_PY" -I -c '
import sys
sys.stdout.write("".join(("line %05d uses %s " % (i, sys.argv[1])).ljust(55, ".") + "\n" for i in range(1, 80001)))' "$PTERM" >"$WORK/t14.txt"
t0="$("$REAL_PY" -I -c 'import time; print(time.time())')"
_text "$WORK/t14.txt"
t1="$("$REAL_PY" -I -c 'import time; print(time.time())')"
secs="$("$REAL_PY" -I -c 'import sys; print("%.1f" % (float(sys.argv[2]) - float(sys.argv[1])))' "$t0" "$t1")"
# T14. RED WHEN: a term's line is counted with count("\n", 0, start) per match, or the report's
# duplicate test is a list search (both quadratic: 80 000 findings then take tens of seconds).
expect_rc "T14: 80 000 lines each holding a term are reported to line 80000" 1 "private-term at demo:80000" @scanned
if "$REAL_PY" -I -c 'import sys; sys.exit(0 if float(sys.argv[1]) < 10 else 1)' "$secs"; then
  ok "T14: 80 000 term findings in a 4.5 MB text take under 10 s (${secs} s)"
else bad "T14: 80 000 term findings in a 4.5 MB text take under 10 s" "${secs} s"; fi

echo "== (n) a long text is also read whole, as gitleaks reads a file"
# A text longer than one gitleaks piece is read in windows and pieces, and also whole, as one more
# chunk: gitleaks decodes encoded text in several passes over the whole file, so a part of a text
# can decode differently from the whole. Each case below compares the guard with whole-file
# gitleaks on the same text (the oracle). Every key, token and value is built at run time.
WHOLEPY="$WORK/whole.py"
cat >"$WHOLEPY" <<'EOF'
import base64, binascii, hashlib, json, os, random, re, shutil, subprocess, sys, tempfile
sys.path.insert(0, sys.argv[1])
import scan
GITLEAKS, RULES, WORK = sys.argv[2], sys.argv[3], sys.argv[4]
def report(name, good, detail=""):
    print(("ok " if good else "bad ") + name + ("" if good else " - " + detail))
dash = b"-" * 5
def pem(n=3000, seed=3):
    rnd = random.Random(seed)
    raw = bytes(rnd.choice(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/") for _ in range(n))
    return (dash + b"BEGIN RSA PRIVATE " + b"KEY" + dash + b"\n" + b"\n".join(raw[i:i + 64] for i in range(0, n, 64))
            + b"\n" + dash + b"END RSA PRIVATE " + b"KEY" + dash + b"\n")
def words(n, seed=5):
    rnd = random.Random(seed)
    out = b""
    while len(out) < n:
        out += b"word %d and more words here\n" % rnd.randint(0, 99999)
    return out[:n]
PEM = pem()
def r64(filler=b"x"):
    return base64.b64encode(filler * 36000 + PEM + filler * 300)
def rhex(filler=b"x"):
    return binascii.hexlify(filler * 18000 + PEM + filler * 300)
def up(s):
    return b"".join(b"U+%04X " % c for c in s)
def ue(s):
    return b"".join(b"\\u%04X" % c for c in s)
def pc(s):
    return b"".join(b"%%%02X" % c for c in s)
def build(lead, trail=b"", filler=b"x", run=r64, rstart=50000, shift=1):
    """Words, then on one line q= + LEAD + an encoded run holding a key + TRAIL, then words to 118 000 bytes."""
    pre = b"q=" + lead
    head = words(max(0, rstart - len(pre) - 1) + shift) + b"\n"
    body = head + pre + run(filler) + trail + b"\n"
    return body + words(max(0, 118000 - len(body)))
def tail_case(enc, extra, shift):
    """A base64 run holding a key whose last EXTRA-odd characters are written as escapes."""
    body = b"x" * 36000 + PEM
    body += b"x" * next(k for k in range(300, 310) if (len(body) + k) % 3 == 0)
    k = base64.b64encode(body)
    cut = len(k) - extra
    cut -= (cut % 4) - 1 if cut % 4 >= 1 else 3
    head = words(50000 + shift - 3) + b"\n"
    line = head + b"q=" + k[:cut] + enc(k[cut:]) + b"\n"
    return line + words(max(0, 118000 - len(line)))

CASES = []  # (class, name, text)
def case(cls, name, text):
    CASES.append((cls, name, text))
# The table: an escape lead glued to a base64 run holding a key (and the run then a trail).
SHIFT0 = {"REAL q=\\u0020*9000+R", "REAL q=\\\\u0020*9000+R", "REAL uesc both sides"}
table = []
for g in range(4):
    table.append(("pct20x60+glue%d" % g, b"%20" * 60 + b"zzzz"[:g], b"", b"x"))
for k in (60, 61, 62, 63):
    table.append(("pct41x%d" % k, b"%41" * k, b"", b"x"))
for k in (60, 61, 62, 63):
    table.append(("uesc0020x%d" % k, b"\\u0020" * k, b"", b"x"))
for k in (60, 61, 62, 63):
    table.append(("uesc0041x%d" % k, b"\\u0041" * k, b"", b"x"))
table.append(("uesc2bs0020x60", b"\\\\u0020" * 60, b"", b"x"))
for m in (16, 17, 18, 19):
    table.append(("hex20x%d fillA" % m, b"20" * m, b"", b"A"))
    table.append(("hex20x%d fillx" % m, b"20" * m, b"", b"x"))
for k in (1, 2, 3):
    table.append(("Uplus0020x60+U+0020glued" + "k%d" % k, b"U+0020 " * 60 + b"U+0020" + b"zzz"[:k - 1], b"", b"x"))
table.append(("Uplus0020x60 spaced", b"U+0020 " * 60, b"", b"x"))
for g in range(4):
    table.append(("pct20x60+%dhexdig" % g, b"%20" * 60 + b"012"[:g], b"", b"A"))
table.append(("rev R+pct20x60", b"", b"%20" * 60, b"x"))
table.append(("rev R+uesc0020x60", b"", b"\\u0020" * 60, b"x"))
for m in (16, 17, 18, 19):
    table.append(("rev R+hex20x%d" % m, b"", b"20" * m, b"x"))
table.append(("rev pct20 both sides", b"%20" * 60, b"%20" * 60, b"x"))
table.append(("REAL q=%20*15000+R", b"%20" * 15000, b"", b"x"))
table.append(("REAL q=\\u0020*9000+R", b"\\u0020" * 9000, b"", b"x"))
table.append(("REAL q=%41*15001+R", b"%41" * 15001, b"", b"x"))
table.append(("pct both sides long, spaced", b"%20" * 15000 + b" ", b" " + b"%20" * 10, b"x"))
table.append(("pct20x60 spaced", b"%20" * 60 + b" ", b"", b"x"))
table.append(("REAL q=%20*15000+R+%20", b"%20" * 15000, b"%20", b"x"))
table.append(("REAL q=\\\\u0020*9000+R", b"\\\\u0020" * 9000, b"", b"x"))
table.append(("pct00 nonprintable + R", b"%20" * 59 + b"%00", b"", b"x"))
table.append(("pct QUJD wordchars + R", b"%20" * 56 + b"%51%55%4A%44", b"", b"x"))
table.append(("uesc QUJD wordchars + R", b"\\u0020" * 56 + b"\\u0051\\u0055\\u004A\\u0044", b"", b"x"))
table.append(("pct20 + hex20x16 + R fillA", b"%20" * 60 + b"20" * 16, b"", b"A"))
table.append(("REAL q=%20*15000+R+%20 fillA", b"%20" * 15000, b"%20", b"A"))
table.append(("REAL uesc both sides", b"\\u0020" * 9000, b"\\u0020", b"x"))
for name, lead, trail, filler in table:
    case("table", name, build(lead, trail, filler, shift=0 if name in SHIFT0 else 1))
# Nested escapes: an escape of an escape, decoded over more than one pass.
for name, lead, filler in (("%2520x60", b"%2520" * 60, b"x"), ("%5Cu0020x60", b"%5Cu0020" * 60, b"x"),
                           ("\\u002520x60", b"\\u002520" * 60, b"x"), ("%20x60+%2520", b"%20" * 60 + b"%2520", b"x"),
                           ("%20x60+%25%320", b"%20" * 60 + b"%25%320", b"x"), ("%252520x60", b"%252520" * 60, b"x"),
                           ("%2520x60 fillA", b"%2520" * 60, b"A")):
    case("nested", name, build(lead, b"", filler))
# Every offset: 0 to 3 bytes between the lead and a base64 run, 0 to 1 before a hex run.
for lead in (b"%20", b"\\u0020", b"%2520", b"%5Cu0020", b"%25%320", b"%252520", b"U+0020 ", b"20"):
    for rname, run, pads in (("b64", r64, (b"", b"A", b"AA", b"AAA", b".", b"..", b"...")), ("hex", rhex, (b"", b"a", b"."))):
        for pad in pads:
            case("offset", "%sx60 pad=%r R=%s" % (lead.decode(), pad.decode(), rname), build(lead * 60 + pad, run=run))
# The same with a long lead (q= then 15 000 escapes), so the encoded text is longer than WINDOW.
LONG = {("%2520", "", "b64"): (115097, 0), ("%2520", "A", "b64"): (50000, 0), ("%2520", "AA", "b64"): (50000, 0),
        ("%2520", "AAA", "b64"): (50000, 0), ("%2520", ".", "b64"): (113321, 0), ("%2520", "..", "b64"): (111545, 2),
        ("%2520", "...", "b64"): (111546, 0), ("\\u0020", "", "b64"): (112327, 0), ("\\u0020", "A", "b64"): (50000, 0),
        ("\\u0020", "AA", "b64"): (50000, 0), ("\\u0020", "AAA", "b64"): (50000, 0), ("\\u0020", ".", "b64"): (112328, 1),
        ("\\u0020", "..", "b64"): (112329, 0), ("\\u0020", "...", "b64"): (112330, 0), ("%2520", "", "hex"): (122205, 0),
        ("%2520", "a", "hex"): (50000, 0), ("%2520", ".", "hex"): (123983, 0), ("\\u0020", "", "hex"): (121212, 0),
        ("\\u0020", "a", "hex"): (50000, 0), ("\\u0020", ".", "hex"): (50000, 0)}
for lead in (b"%20", b"%2520", b"\\u0020"):
    for rname, run, pads in (("b64", r64, (b"", b"A", b"AA", b"AAA", b".", b"..", b"...")), ("hex", rhex, (b"", b"a", b"."))):
        for pad in pads:
            rstart, shift = LONG.get((lead.decode(), pad.decode(), rname), (50000, 1))
            case("long lead", "q=%sx15000 pad=%r R=%s" % (lead.decode(), pad.decode(), rname),
                 build(lead * 15000 + pad, run=run, rstart=rstart, shift=shift))
# A lead whose decoded text ends in base64 characters that join the run: E(D[:-t]) + D[-t:].
for n in (10, 30, 300):
    d = base64.b64encode(b"xxx" * n)
    for en, f in (("U+", up), ("\\u", ue), ("%", pc)):
        for t in (1, 2, 3, 5, 6):
            case("joined lead", "%s N=%d t=%d" % (en, n, t), build(f(d[:-t]) + d[-t:]))
# A run whose last characters are written as escapes (the text after the run).
for en, f, shift in (("\\u", ue, 1), ("U+", up, 0), ("%", pc, 1)):
    for extra in (40, 400):
        case("escaped tail", "%s tail=%d" % (en, extra + 3), tail_case(f, extra, shift))
# Two runs of U+ escapes with two plain letters between them: decoded, they join into one run.
for size in (3000, 1000, 300):
    for nl in (True, False):
        a = up(b"ICAg" * 3143 + b"I")
        if nl:
            a = a[:-1] + b"\n"
        text = b"!!" + a + b"CA" + up(b"g" + base64.b64encode(pem(size)))
        case("across a gap", "key of %d, %s" % (size, "line break" if nl else "space"), text + b"!" * max(0, 118000 - len(text)))
# Escapes, a hyphen, then percent escapes glued to the run.
for shift in range(4):
    head = words(50000 + shift) + b"\n"
    text = head + b"\\u0041" * 400 + b"-" + b"%49%43%41%67" + r64() + b"\n"
    case("escapes and a hyphen", "shift %d" % shift, text + words(max(0, 118000 - len(text))))
# Seeded layouts: a long escape lead before a run holding a key, over 105 000 to 200 000 bytes;
# every fourth one has "ustar" at byte 257, so gitleaks reads it as a tar file.
LEADS = [b"%20", b"\\u0020", b"%2520", b"U+0020 ", b"%41", b"\\u0041"]
def layout(seed):
    rnd = random.Random(seed)
    body = b"x" * rnd.randint(10000, 40000) + PEM + b"x" * rnd.randint(0, 400)
    run = base64.b64encode(body) if rnd.random() < 0.7 else binascii.hexlify(body)
    u = rnd.choice(LEADS)
    lead = u * rnd.randint(2000, 16000) + bytes(rnd.choice(b"A.a") for _ in range(rnd.randint(0, 3)))
    line = rnd.choice([b"q=", b" ", b""]) + lead + run
    head = words(rnd.randint(1000, 60000), seed=seed) + b"\n"
    data = head + line + b"\n"
    return data + words(max(0, rnd.randint(105000, 200000) - len(data)), seed=seed + 1)
for seed in range(9040, 9080):
    text = layout(seed)
    if seed % 4 == 0:
        text = text[:257] + b"ustar" + text[262:]
    case("seeded", "seed %d%s" % (seed, ", ustar at 257" if seed % 4 == 0 else ""), text)

# The oracle: gitleaks (default rules, then the public rules) reading each text as one file, behind
# 100 000 line breaks so that no text is skipped as a binary file; lines are counted back.
def oracle(texts):
    d = tempfile.mkdtemp(dir=WORK)
    for i, t in enumerate(texts):
        with open(os.path.join(d, "f%04d" % i), "wb") as fh:
            fh.write(b"\n" * 100000 + t)
    out = [set() for _ in texts]
    for extra in ([], ["--config", RULES]):
        rep = os.path.join(WORK, "oracle.json")
        subprocess.run([GITLEAKS, "dir", d, "--no-banner", "--ignore-gitleaks-allow", "--report-format", "json",
                        "--report-path", rep, "--exit-code", "0", "--log-level", "error"] + extra, check=True)
        for f in json.load(open(rep)):
            out[int(os.path.basename(f["File"])[1:])].add((f["RuleID"], int(f["StartLine"]) - 100000))
    shutil.rmtree(d)
    return out
texts = [t for _c, _n, t in CASES]
want = oracle(texts)
# The guard, through Scanner.run(): every text one place. The raw findings are kept beside the
# report so that each can be traced to its chunk.
places = ["case-%03d" % i for i in range(len(CASES))]
plans = [scan._plan(t)[0] for t in texts]
got = [set() for _ in texts]
head_part = [set() for _ in texts]
whole_idx = {}
with scan.Scanner(scan.Terms([], None)) as sc:
    for i, t in enumerate(texts):
        start = len(sc.chunks)
        sc.add(places[i], t)
        if (0, len(t)) in plans[i]:
            whole_idx[start + plans[i].index((0, len(t)))] = i
    # The chunk files, byte for byte, before the run.
    files_bad = []
    for i, t in enumerate(texts):
        idxs = [k for k, c in enumerate(sc.chunks) if c["place"] == places[i]]
        whole = 0
        for k, (s0, e0) in zip(idxs, plans[i]):
            raw_file = (sc.src / sc._name(k)).read_bytes()
            tail = b"\n\n" + sc._canary(k).encode()
            if raw_file == t + tail:
                whole += 1
            elif raw_file != b"\n" + t[s0:e0] + tail:
                files_bad.append((CASES[i][1], k, s0, e0))
        if whole != 1 or len(idxs) != len(plans[i]):
            files_bad.append((CASES[i][1], "whole-text files: %d of %d chunks" % (whole, len(idxs))))
    raw = []
    real_findings = sc.findings
    def keep():
        out = real_findings()
        raw.extend(out)
        return out
    sc.findings = keep
    lines = sc.run()
    at = {p: i for i, p in enumerate(places)}
    for ln in lines:
        m = re.fullmatch(r"(\S+) at (case-\d{3}):(\d+)", ln)
        if not m:
            got[0].add(("unparsed", ln))
            continue
        got[at[m.group(2)]].add((m.group(1), int(m.group(3))))
    for rule, idx, line, _t in raw:
        chunk = sc.chunks[idx]
        if chunk["kind"] == "display" or idx in whole_idx:
            continue
        head_part[at[chunk["place"]]].add((rule, line))

classes = sorted({c for c, _n, _t in CASES}, key=[c for c, _n, _t in CASES].index)
# A long text is read whole. RED WHEN: the whole text is not one of a long text's chunks, or that
# chunk is cut short, starts with a byte the text does not have, or its line numbers are off: a
# key that gitleaks reports when it reads the file whole is then missed. Each case: everything
# whole-file gitleaks reports is reported, on the same line.
for cls in classes:
    idx = [i for i, (c, _n, _t) in enumerate(CASES) if c == cls]
    missed = [(CASES[i][1], sorted(want[i] - got[i])) for i in idx if want[i] - got[i]]
    report("A long text is read whole (%s): all %d texts report everything whole-file gitleaks reports, on its line"
           % (cls, len(idx)), not missed, "%d missed, first %s" % (len(missed), missed[:2]))
# A long text is read whole, property. RED WHEN: the whole-text chunk is removed, cut short or
# read with its lines shifted, or the guard reports a finding that neither its other chunks nor
# whole-file gitleaks report (rule, place and line, each once).
bad = [(CASES[i][1], sorted(got[i] ^ (head_part[i] | want[i]))) for i in range(len(CASES)) if got[i] != head_part[i] | want[i]]
report("A long text is read whole, property: on %d texts the report is the other chunks' findings plus whole-file gitleaks'"
       % len(CASES), not bad, "%d differ, first %s" % (len(bad), bad[:2]))
# Partner. RED WHEN: the fixtures change so that the other chunks alone report everything whole-file
# gitleaks reports (the cases above would then pass with no whole-text chunk).
only = sum(1 for i in range(len(CASES)) if want[i] - head_part[i])
keys = sum(1 for i in range(len(CASES)) if any(r == "private-key" for r, _l in want[i]))
report("A long text is read whole, partner: whole-file gitleaks reports a key in 168 texts, and 93 of them hold a finding "
       "only the whole text gives", (keys, only) == (168, 93), "%d with a key, %d only from the whole text" % (keys, only))

# Whole-text chunk, bytes. RED WHEN: a byte is put before the whole text (a line break moves every
# cut gitleaks makes in a long file), the text is cut short, or a chunk does not end with two line
# breaks and its canary line. Each long text has exactly one chunk file that is the text, two
# line breaks and the canary; every other chunk file is a line break, its span, two line breaks
# and the canary.
report("Whole-text chunk, bytes: each of %d long texts has one chunk file that is the text as written" % len(CASES),
       not files_bad, "%d differ, first %s" % (len(files_bad), files_bad[:3]))
# Whole-text chunk, plan. RED WHEN: the whole text is not a span of a long text's plan, is there more
# than once, or the spans are not sorted by their start.
plan_bad = [CASES[i][1] for i, t in enumerate(texts) if plans[i].count((0, len(t))) != 1
            or plans[i] != sorted(plans[i], key=lambda s: s[0])]
report("Whole-text chunk, plan: each of %d long texts has the whole text as one span, once, and sorted spans" % len(CASES),
       not plan_bad, "%d differ, first %s" % (len(plan_bad), plan_bad[:3]))
# Whole-text chunk, plan partner. RED WHEN: a text that fits in one gitleaks piece gets more than its
# one chunk.
short = words(scan.GITLEAKS_PIECE - 100)
report("Whole-text chunk, plan partner: a text of one piece is one chunk", scan._plan(short)[0] == [(0, len(short))],
       str(scan._plan(short)[0][:3]))
# Other chunks unchanged. RED WHEN: a span of the plan other than the whole text is changed, dropped or
# added (the windows and the key and run pieces are pinned, per group of cases, by a digest).
def digest(idx):
    h = hashlib.sha256()
    for i in idx:
        rest = list(plans[i])
        if (0, len(texts[i])) in rest:
            rest.remove((0, len(texts[i])))
        h.update(repr(rest).encode() + b";")
    return h.hexdigest()[:16]
PINNED = {"table": "474cd94fb8f7b434", "nested": "fb408aadf3803fe3", "offset": "320f18e9976c490e",
          "long lead": "e35956b296383757", "joined lead": "c478c0a17e79279e", "escaped tail": "c2e64cd326358a5a",
          "across a gap": "ca26a7109bcc9743", "escapes and a hyphen": "d11749e4bfbbad2e", "seeded": "025b07ea32820dfb"}
for cls in classes:
    d = digest([i for i, (c, _n, _t) in enumerate(CASES) if c == cls])
    report("Other chunks unchanged: the %s cases keep their windows and pieces" % cls, d == PINNED.get(cls), "digest %s" % d)

# Two texts for the retry cases in the shell part: a key only the whole text gives, on line 1 and
# on a later line (the line whole-file gitleaks gives is written beside each).
for name, cls, case_name in (("whole-line1", "across a gap", "key of 3000, line break"),
                             ("whole-late", "joined lead", "U+ N=10 t=1")):
    i = next(k for k, (c, n, _t) in enumerate(CASES) if (c, n) == (cls, case_name))
    with open(os.path.join(WORK, name + ".txt"), "wb") as fh:
        fh.write(texts[i])
    with open(os.path.join(WORK, name + ".line"), "w") as fh:
        fh.write("%d\n" % min(l for r, l in want[i] if r == "private-key"))

# Values at the very end of a text. Each value is written as U+ escapes, the last escape with
# nothing after it, in a short text (one piece) and in a long one; built here, so no file holds it.
rnd = random.Random(9)
def pick(alphabet, n):
    return bytes(rnd.choice(alphabet) for _ in range(n))
VALUES = (("aws-access-token", b"AK" + b"IA" + pick(b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", 16)),
          ("openrouter-api-key", b"sk-" + b"or-v1-" + pick(b"0123456789abcdef", 64)),
          ("home-folder-path", b"/" + b"Users/" + b"jdoe"),
          ("generic-api-key", b"api_" + b"token = " + pick(b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJ0123456789", 32)))
ends = []
for rule, value in VALUES:
    for pad in (60, 150000):
        for tail in (b"", b"\n"):
            body = b"lorem ipsum dolor\n" * (pad // 18)
            ends.append((rule, pad, tail, body + b"x " + up(value).rstrip(b" ") + tail))
end_want = oracle([t for _r, _p, _tail, t in ends])
end_got = [set() for _ in ends]
with scan.Scanner(scan.Terms([], None)) as sc:
    for i, (_r, _p, _tail, t) in enumerate(ends):
        sc.add("end-%02d" % i, t)
    for ln in sc.run():
        m = re.fullmatch(r"(\S+) at end-(\d{2}):(\d+)", ln)
        if m:
            end_got[int(m.group(2))].add((m.group(1), int(m.group(3))))
for i, (rule, pad, tail, t) in enumerate(ends):
    size = "one piece" if len(t) <= scan.GITLEAKS_PIECE - 100 else "a long text"
    where = "with nothing after it" if not tail else "then a line break"
    line = t.count(b"\n") + (0 if tail else 1)
    # Value at the end, partner. RED WHEN: the fixture stops being a value whole-file gitleaks
    # reports on its line.
    if not tail and pad == 60:
        report("Value at the end, partner: whole-file gitleaks reports the U+-escaped %s value" % rule,
               (rule, line) in end_want[i], str(sorted(end_want[i])))
    # Value at the end. RED WHEN: a chunk's text is followed by only one line break before its
    # canary line (a value written as escapes at the very end of a text is then missed). With a
    # line break after the value, the case is a partner: it is found either way.
    report("Value at the end: a U+-escaped %s value at the end of %s, %s, is reported on line %d" % (rule, size, where, line),
           end_got[i] == end_want[i] and (rule, line) in end_got[i],
           "got %s, whole-file %s" % (sorted(end_got[i]), sorted(end_want[i])))

# Line numbers of a long text. RED WHEN: the report's duplicate test is removed, or the whole-text
# chunk's lines are off by one (a finding on line 1 is then reported twice, on two lines). The
# token is a GitHub token shape built at run time.
tok = lambda: b"gh" + b"p_" + pick(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", 36)
body = b"\n".join(b"word %d filler text here" % i for i in range(6000))
for label, text, line in (("on line 1", tok() + b"\n" + body + b"\n", 1),
                          ("on the last line, with nothing after it", body + b"\n" + tok(), 6001)):
    with scan.Scanner(scan.Terms([], None)) as sc:
        sc.add("demo", text)
        out = [ln for ln in sc.run() if ln.startswith("github-pat ")]
    report("Line numbers of a long text: a token %s is reported once, on line %d" % (label, line),
           out == ["github-pat at demo:%d" % line], str(out))
# Private terms of a long text. RED WHEN: more than one chunk of a long text is matched for
# private terms (the whole-text chunk too): the term is then found twice. The same case shows it
# is found.
term = "zebra" + "corn"
text = body + b"\nwe build " + term.encode() + b" next\n" + body
with scan.Scanner(scan.Terms([term], None)) as sc:
    sc._pass = lambda exe, cfg, n: []
    sc.add("demo", text)
    hits = [(line, t) for rule, _idx, line, t in sc.findings() if rule == "private-term"]
report("Private terms of a long text: the term on line 6001 is found once", hits == [(6001, term)], str(hits))
EOF
mkdir -p "$WORK/whole" || die "mkdir whole"
py_verdicts "$WHOLEPY" "$ROOT/public-content" "$REAL_GITLEAKS" "$RULES" "$WORK/whole"
# whole_case NAME FILE LINE MODE: text mode with the MODE wrapper first on PATH; exit 1 and the
# report names the key on exactly LINE.
whole_case() {
  rm -f "$WORK/wrap-$4.state"
  PATH="$WORK/wrap-$4:$PATH" _text "$2"
  if [ "$(rc)" = 1 ] && grep -q -x -F -e "  - private-key at demo:$3" "$ERR" && [ -s "$GLLOG" ] && ! _leaks "$OUT" "$ERR"; then
    ok "$1"
  else
    bad "$1" "exit $(rc)$(_hint)"
  fi
}
for f in whole-line1 whole-late; do
  [ -s "$WORK/whole/$f.txt" ] && [ -s "$WORK/whole/$f.line" ] || die "whole fixture $f"
  wl="$(cat "$WORK/whole/$f.line")"
  # Whole text (end to end). RED WHEN: a long text is not also read whole, or that chunk's lines are
  # off: a key that whole-file gitleaks reports is missed or put on another line.
  whole_case "Whole text: a key only the whole text gives is reported on line $wl" "$WORK/whole/$f.txt" "$wl" pass
  # Whole text, read again. RED WHEN: the whole-text chunk read again behind the 100 000 line breaks
  # (after gitleaks skipped every chunk once) is read with a byte more or less before the text, or
  # its lines are counted from the wrong start.
  whole_case "Whole text, read again: the same key is reported on line $wl when every chunk is read a second time" \
    "$WORK/whole/$f.txt" "$wl" skiponce
done

echo
echo "${PASS} passed, ${FAIL} failed, ${SKIPPED} skipped"
[ "$FAIL" -eq 0 ]
