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
#     that is not a letter or digit when one is near, each with its own canary. Every key block
#     of such a text is also read on its own (blocks do not overlap; one over 90 000 bytes -> 2).
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
expect_rc "a key block too long for one piece blocks" 2 "could not check" "private key block crosses a scan window"
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
import base64, sys
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
            "dotted-i": (begin(i=DOTI), end())}[v]
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
import random, re, sys
sys.path.insert(0, sys.argv[1])
import scan
W, OV, E = scan.WINDOW, scan.OVERLAP, scan.EDGE
dash = "-" * 5
def report(name, good, detail=""):
    print(("ok " if good else "bad ") + name + ("" if good else " - " + detail))
def bound(n):
    return 9 * n // 4 + 2 * W
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
# T1. RED WHEN: a key block starts at its line start (rfind), or a block a window holds is
# chunked again (the chunk bytes then grow far past 2.25 times the text).
for label, text in texts:
    written = []
    with scan.Scanner(scan.Terms([], None)) as sc:
        sc._write = lambda meta, chunk, shift, terms: written.append(len(chunk))
        try:
            sc.add("demo", text)
            report("T1: %s: chunk bytes within 9n/4 + 2W" % label, sum(written) <= bound(len(text)),
                   "%d bytes in %d chunks for %d" % (sum(written), len(written), len(text)))
        except scan.ScanError as exc:
            report("T1: %s: chunk bytes within 9n/4 + 2W" % label, False, "ScanError: %s" % exc)
# T1 (plan). RED WHEN: as above, or key spans overlap, or their count passes I4's.
for label, text in texts:
    name = "T1: %s: the plan's key spans are disjoint and within the bound" % label
    try:
        spans, too_long = scan._plan(text)
    except AttributeError as exc:
        report(name, False, "no planner (%s)" % exc)
        continue
    keys = sorted(keys_of(spans, scan._windows(text)))
    n = len(text)
    good = (sum(e - s for s, e in spans) <= bound(n) and not too_long
            and all(a[1] <= b[0] for a, b in zip(keys, keys[1:]))
            and len(spans) <= n / 72000 + n / 14000 + 2)
    report(name, good, "%d spans, %d key spans, %d bytes, too long %s" % (
        len(spans), len(keys), sum(e - s for s, e in spans), too_long))

# T8. RED WHEN: the planner's size check is removed (overlapping key spans then pass silently).
text = b"!" * 200000
name = "T8: the planner refuses key spans past its size bound"
real = getattr(scan, "_key_spans", None)
try:
    scan._key_spans = lambda t: [(80000, 170000)] * 100
    scan._plan(text)
    report(name, False, "no error")
except scan.ScanError as exc:
    report(name, "exceeds its size bound" in str(exc), "other error: %s" % exc)
except AttributeError as exc:
    report(name, False, "no planner (%s)" % exc)
finally:
    if real is not None:
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
    "\u20ac", "\udcff", "\u0130", "-", "\n", "A" * 10, "ab+/")] + [b"\xe2\x84"]
# T15. RED WHEN: _windows advances by more than WINDOW - OVERLAP + EDGE, key spans overlap, or
# body_end counts bytes (an oracle match then lies in no chunk).
fails = []
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
    wins = scan._windows(text)
    keys = sorted(keys_of(spans, wins))
    n = len(text)
    i1 = (wins[0][0] == 0 and wins[-1][1] == n and all(e - s <= W for s, e in wins)
          and all(b[0] - a[0] >= W - OV - E and b[0] <= a[1] - (OV - E) for a, b in zip(wins, wins[1:])))
    held = lambda a, b: any(s <= a and b <= e for s, e in wins)
    i3 = (all(a[1] <= b[0] for a, b in zip(keys, keys[1:])) and all(e - s <= W for s, e in keys)
          and not any(held(s, e) for s, e in keys))
    found = oracle(text)
    missed = [m for m in found if m[1] - m[0] <= W and not any(s <= m[0] and m[1] <= e for s, e in spans)]
    longer = [m for m in found if m[1] - m[0] > W]
    if not (i1 and i3) or missed or (longer and not too_long):
        fails.append("text %d: I1 %s, I3 %s, %d oracle matches in no chunk, %d too long (flag %s)" % (
            it, i1, i3, len(missed), len(longer), too_long))
report("T15: 300 fuzz texts: every oracle match lies in a planned chunk; I1-I3 hold", not fails,
       "; ".join(fails[:3]) + (" (%d texts)" % len(fails) if fails else ""))
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
for v in ascii kelvin-begin kelvin-end long-s; do
  _kgen pemv "$WORK/pemv.txt" 70000 50000 "$v" >/dev/null
  # RED WHEN: the fixture stops being a key gitleaks itself reports when read whole.
  if gl_finds "$WORK/pemv.txt.block" private-key; then ok "T4: gitleaks reports the $v block read whole"; else
    bad "T4: gitleaks reports the $v block read whole" "not reported"; fi
  _text "$WORK/pemv.txt"
  # T4. RED WHEN: the U+212A or U+017F alternative is removed from the marker regexes, or they
  # become a str (?i) regex.
  expect_rc "T4: a 50 KB key ($v) from byte 70 000 of a long line is found" 1 "private-key at demo:2" @scanned
done
_kgen pemv "$WORK/pemv.txt" 70000 50000 dotted-i >/dev/null
if gl_finds "$WORK/pemv.txt.block" private-key; then bad "T4: gitleaks does not report a BEGIN with a dotted capital I" "reported"; else
  ok "T4: gitleaks does not report a BEGIN with a dotted capital I"; fi
_text "$WORK/pemv.txt"
# T4 partner. RED WHEN: the marker regex folds U+0130 to i, which gitleaks does not (a str (?i) regex).
expect_rc "T4: a key whose BEGIN has a dotted capital I is clean, as in gitleaks" 0 @scanned
for v in kelvin-key kelvin-block; do
  _kgen pgpv "$WORK/pgpv.txt" 70000 "$v" >/dev/null
  if gl_finds "$WORK/pgpv.txt.block" private-key; then ok "T5: gitleaks reports the PGP $v block read whole"; else
    bad "T5: gitleaks reports the PGP $v block read whole" "not reported"; fi
  _text "$WORK/pgpv.txt"
  # T5. RED WHEN: the K alternative is missing from the END regex (in KEY or in BLOCK).
  expect_rc "T5: a PGP key whose END has a Kelvin sign ($v) is found" 1 "private-key at demo:2" @scanned
done
_kgen euro "$WORK/euro.txt" 70000 >/dev/null
if gl_finds "$WORK/euro.txt.block" private-key; then ok "T6: gitleaks reports the euro-sign block read whole"; else
  bad "T6: gitleaks reports the euro-sign block read whole" "not reported"; fi
_text "$WORK/euro.txt"
# T6. RED WHEN: body_end counts bytes, not characters (the span then ends at the first END and
# gitleaks' real 25 KB match is cut between two windows).
expect_rc "T6: a key whose first END is under 64 characters after BEGIN is found" 1 "private-key at demo:2" @scanned
sline="$(_kgen swallow "$WORK/swallow.txt" 68000)"
_text "$WORK/swallow.txt"
# T15b. RED WHEN: BEGIN markers are found with finditer (the greedy header of a BEGIN inside key
# A swallows the next real BEGIN, and its 25 KB key is in no chunk).
expect_rc "T15b: a key after a line holding two BEGIN markers is found with the key before it" 1 \
  "private-key at demo:2" "private-key at demo:$sline" @scanned

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
# T11. RED WHEN: the look-arounds go back to [A-Za-z0-9] (a cased letter or digit of any
# script, or a mark on one, touching the term must make it part of a longer word).
case("T11: e-acute before the term", A, "\u00e9acme", [])
case("T11: e-acute after the term", A, "acme\u00e9", [])
case("T11: an Arabic-Indic digit before the term", A, "\u0663acme", [])
case("T11: a combining acute on the term's last letter", A, "acme\u0301", [])
case("T11 partner: a-acute in place of the term's a", A, "\u00e1cme", [])
case("T11 partner: a hyphen and an underscore are breaks", A, "x-acme_y", ["acme"])
case("T11 partner: two hits on one line", A, "acme acme", ["acme", "acme"])
# T11b. RED WHEN: the word test reads folded characters, a mark counts as a word character
# whatever its base, or letters of type Lm, Nl or No count as word characters.
for label, text, got in (("a trade mark sign", "Acme\u2122 Labs", "Acme"), ("a numero sign", "\u2116acme", "acme"),
                         ("a Han letter before", "\u793eacme", "acme"), ("a Han letter after", "acme\u793e", "acme"),
                         ("a Thai letter with a tone mark", "\u0e01\u0e48acme", "acme"),
                         ("Katakana with a length mark", "\u30b5\u30fc\u30d0\u30fcacme", "acme"),
                         ("Thai with a repetition mark", "\u0e14\u0e35\u0e46acme", "acme"),
                         ("an ideographic iteration mark", "acme\u3005", "acme"),
                         ("an ideographic zero", "\u3007acme", "acme")):
    case("T11b: the term next to %s is found" % label, A, text, [got])
# T11c. RED WHEN: units are folded one character at a time (NFC and NFD spellings then differ),
# or ignorable characters are not skipped.
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

echo
echo "${PASS} passed, ${FAIL} failed, ${SKIPPED} skipped"
[ "$FAIL" -eq 0 ]
