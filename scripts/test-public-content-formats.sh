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
expect_rc "diff-tree: the ':' path is found under its name" 1 "home-folder-path at :lead.txt:1"
expect_rc "diff-tree: the path named like a commit sha is found under its name" 1 "home-folder-path at $C1:1"
expect_rc "diff-tree: the merge resolution is found under its name" 1 "home-folder-path at conf.txt:2"
n_items="$(grep -c '^  - ' "$ERR")"
if [ "$n_items" = 3 ]; then ok "diff-tree: exactly three findings in the range"; else bad "diff-tree: exactly three findings in the range" "got $n_items$(_hint)"; fi

echo
echo "${PASS} passed, ${FAIL} failed, ${SKIPPED} skipped"
[ "$FAIL" -eq 0 ]
