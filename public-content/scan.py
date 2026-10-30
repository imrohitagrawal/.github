#!/usr/bin/env python3
"""Public-content scanner: finds content that must not be published to a PUBLIC repository.

It finds secrets (gitleaks' default rules) and content that is not a credential but must not
be public: home-folder paths, Claude Code's encoded home-folder names, email addresses,
session transcript names, agent tool and session ids, session links (rules in
gitleaks-public.toml), and private terms (read at run time from a private list, never
committed).

Used by hooks/pre-push (what a push publishes) and by the CI step (a PR's title, body and
commits). CLI modes:

    scan.py text --label LABEL                       scan stdin
    scan.py pre-push REMOTE URL                      git's pre-push protocol (refs on stdin)
    scan.py ci [--repo DIR] --base REV --head REV    PR_TITLE, PR_BODY and the new content

Everything a change publishes is checked whole: each file a new commit adds or changes
(content and path name, even when the same content exists elsewhere), the path of each
embedded repository (gitlink) a new commit adds or changes (not its content), each new commit
and tag (message, names and addresses), and each ref name (pushes only). Text that is already
public is no reason to pass. What passes: the addresses in allowed-addresses.txt (public on
purpose), the rules' own allowlists, and, on author, committer and tagger lines only, the
configured user.email or an address already used as an author or committer on the
destination's history.

How content is read (as_text, unpack). The guard reads these formats itself and hands gitleaks
plain text:
- Text (no NUL byte): as it is.
- A file with a UTF-16 or UTF-32 byte-order mark: decoded as that encoding, besides the other
  views (such a file usually holds NUL bytes, so it is also read as a binary).
- zip, tar, gzip, bzip2 and xz, up to ARCHIVE_DEPTH archives deep: every file inside, after
  proving every byte of the archive is accounted for (zip entries back to back to the central
  directory, each local header agreeing with it, and one end record ending the file, read
  with methods stored, deflate and bzip2 only; tar header records back to back, each padded
  with NUL bytes, the extension headers (pax records, GNU long names) read as content, then
  NUL bytes or another tar; compressed streams of one format, with only NUL padding between
  and after).
  An archive that cannot be read completely blocks, as do encryption, deeper nesting, more
  than UNPACK_LIMIT unpacked from one file, and the formats the guard cannot open (7z, rar,
  zstd, lz4 (frame format), lzip, Unix compress, cabinet, xar), found by their leading signature at
  the top level and inside archives. Every layer of nesting counts against UNPACK_LIMIT.
- Any other data holding a NUL (a binary): its printable runs of MIN_RUN or more characters,
  as 7-bit text and as UTF-16 and UTF-32 units, plus the bytes as they are when they decode as
  strict UTF-8. Documented gaps, not blocked: shorter runs; runs broken by non-ASCII
  characters; text inside a binary's compressed parts (PDF streams, image data) and formats
  with no recognisable signature (brotli, raw zlib, lzma-alone); an archive of another format
  that does not start the file (only its printable runs are read); a zip glued after other
  data is read only when Python's zipfile opens it (best effort), which it does not when the
  end record is followed by more than about 64 KB of other data; compressed data deliberately
  placed inside a zip entry's extra field or the zip comment is not read (these are read only
  through their printable text): the guard is meant to catch mistakes, not a determined
  adversary.
gitleaks skips a file it sniffs as a binary format, logging only at debug level, and passes a
file it could not open; so every chunk carries a canary line that proves it was read, and a
chunk without its canary is read once more behind newlines, or the check blocks.

Exit status: 0 clean, 1 findings, 2 error. Every caller treats an error as a block: a check
that could not run never counts as a pass. Reports name the rule and the place, never the
matched text. Lines that look like reported speech print a WARNING and never block (not
raised from a binary's printable runs).

Standard library only (Python 3.9+), plus the gitleaks binary and, for visibility, gh.
"""

from __future__ import annotations

import argparse
import bz2
import io
import json
import lzma
import math
import os
import re
import secrets
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile
import time
import zipfile
import zlib
from pathlib import Path
from typing import Callable

HERE = Path(__file__).resolve().parent
PUBLIC_RULES = HERE / "gitleaks-public.toml"
ALLOWED_ADDRESSES = HERE / "allowed-addresses.txt"
VISIBILITY_TTL = 24 * 3600
GITLEAKS_TIMEOUT = 900
ARCHIVE_DEPTH = 3
UNPACK_LIMIT = 512 * 1024 * 1024  # bytes unpacked from one file, counted at every layer of nesting
STREAM_COST = 4096  # budget each compressed stream costs besides its output
MIN_RUN = 12  # characters in a printable run of a binary that the rules read
RETRY_PREFIX = b"\n" * 100_000  # put before a chunk gitleaks skipped, so it cannot sniff a format
NOTES_KEY = "public-content.notesDir"
TERMS_FILE = Path("scanner") / "private-terms.txt"
SHA_RE = r"[0-9a-f]{40}|[0-9a-f]{64}"
TESTED_GITLEAKS = "8.30.1"  # the version whose log lines the parser below expects
FIX_PUSH = (
    "Fix: amend or rebase the commits to remove it, then push again. "
    "Do not bypass the guard with --no-verify; if this is a false positive, open an issue in the "
    "guard's repository (describe it; do not paste the matched text)."
)


class ScanError(Exception):
    """A check that could not be completed. Every caller blocks on it (fail closed)."""


def _zero(sha: str) -> bool:
    return re.fullmatch(r"0+", sha) is not None


# --------------------------------------------------------------------------- private terms


class Terms:
    """The private terms, and how to find and mask them."""

    def __init__(self, terms: list[str], warning: str | None) -> None:
        self.warning = warning
        parts = []
        for term in terms:
            words = [w for w in re.split(r"[-_. ]+", term) if w]
            if words:
                parts.append("[-_. ]?".join(re.escape(w) for w in words))
        self.alternation = "|".join(parts)
        self.mask_re = re.compile("(?:" + self.alternation + ")", re.IGNORECASE) if parts else None
        # Not inside a longer word of letters and digits; `_` and other marks are breaks. The
        # look-around consumes nothing, so two terms side by side are both found.
        self.find_re = (re.compile("(?<![A-Za-z0-9])(?:" + self.alternation + ")(?![A-Za-z0-9])", re.IGNORECASE)
                        if parts else None)

    def mask(self, text: str) -> str:
        if self.mask_re is not None:
            text = self.mask_re.sub("<private>", text)
        for rx in _public_regexes():
            text = rx.sub("<redacted>", text)
        return text


def _recorded_notes_dir() -> str | None:
    """The notes folder the installer recorded in global git config, or None."""
    try:
        r = subprocess.run(["git", "config", "--global", "--get", NOTES_KEY], stdin=subprocess.DEVNULL,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=30)
    except FileNotFoundError:
        return None  # no git: nothing can have been recorded
    except (OSError, subprocess.SubprocessError) as exc:
        raise ScanError(f"git config could not run ({type(exc).__name__})") from None
    if r.returncode == 1:
        return None  # not set
    if r.returncode != 0:
        raise ScanError(f"git config failed (exit {r.returncode}) while reading {NOTES_KEY}")
    return r.stdout.strip() or None


def _same_folder(a: str, b: str) -> bool:
    return os.path.realpath(os.path.expanduser(a)) == os.path.realpath(os.path.expanduser(b))


def load_terms() -> Terms:
    """Where the list lives: PRIVATE_NOTES_DIR, else the folder recorded in global git config.
    Both set and naming different folders: ScanError (the variable must not silently replace
    the recorded list). Neither set: no private terms, with a warning (CI, other machines).
    A folder whose list is missing, unreadable or empty: ScanError (fail closed)."""
    env = os.environ.get("PRIVATE_NOTES_DIR") or None
    recorded = _recorded_notes_dir()
    if env and recorded and not _same_folder(env, recorded):
        raise ScanError(f"the private notes folder was overridden: PRIVATE_NOTES_DIR names a different "
                        f"folder than the one recorded in git config {NOTES_KEY}")
    base = env or recorded
    if not base:
        return Terms([], "public-content guard: warning: no private notes folder is set "
                         "(PRIVATE_NOTES_DIR), so the private term list was not checked")
    where = f"<private notes folder>/{TERMS_FILE.as_posix()}"
    path = Path(os.path.expanduser(base)) / TERMS_FILE
    try:
        text = path.read_text(encoding="utf-8-sig")
    except (OSError, UnicodeDecodeError) as exc:
        raise ScanError(f"the private term list ({where}) could not be read ({type(exc).__name__})") from None
    terms = [ln.strip() for ln in text.splitlines() if ln.strip() and not ln.lstrip().startswith("#")]
    found = Terms(terms, None)
    if not found.alternation:
        raise ScanError(f"the private term list ({where}) is empty")
    return found


_PUBLIC_CACHE: list[re.Pattern[str]] | None = None
_PUBLIC_IDS: set[str] | None = None


def _public_regexes() -> list[re.Pattern[str]]:
    """The public rules' regexes, for masking places (over-masking is harmless). Compiled with
    ASCII meanings for \\b and \\w, as gitleaks' engine reads them. A regex Python cannot
    compile is a ScanError: masking must not quietly do nothing."""
    global _PUBLIC_CACHE, _PUBLIC_IDS
    if _PUBLIC_CACHE is None:
        text = PUBLIC_RULES.read_text(encoding="utf-8")
        regs = []
        for raw in re.findall(r"(?m)^regex\s*=\s*'''(.*)'''\s*$", text):
            try:
                regs.append(re.compile(raw, re.ASCII))
            except re.error:
                raise ScanError("a public rule's regex cannot be used to mask the report") from None
        _PUBLIC_CACHE = regs
        _PUBLIC_IDS = set(re.findall(r'(?m)^id\s*=\s*"([^"]+)"', text))
    return _PUBLIC_CACHE


def _public_ids() -> set[str]:
    _public_regexes()
    return set(_PUBLIC_IDS or ()) | {"private-term"}


def allowed_addresses() -> set[str]:
    """The addresses that are public on purpose (lowercased), one per line of
    allowed-addresses.txt; `#` starts a comment. A missing file or a line that is not an
    address is a ScanError: a broken list must not quietly allow or block anything."""
    try:
        text = ALLOWED_ADDRESSES.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise ScanError(f"the allowed address list could not be read ({type(exc).__name__})") from None
    out = set()
    for n, line in enumerate(text.splitlines(), 1):
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        if not re.fullmatch(r"[A-Za-z0-9._%+-]+@(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}", line):
            raise ScanError(f"line {n} of the allowed address list is not an address")
        out.add(line.lower())
    return out


# --------------------------------------------------------------------------- reported speech

_SPEECH = (
    re.compile(r"(?i)\bthe owner (?:said|asked|typed|wrote|told|wants|chose|answered|replied)\b"),
    re.compile(r"(?i)\bowner(?:'|’)s (?:exact|own) words\b"),
    re.compile(r"^[ \t]{0,3}>"),
)


def speech_warnings(place: str, data: bytes | str) -> list[str]:
    """Lines that look like someone's words quoted (reported speech about "the owner", a
    common way for an agent to name the person it works for, or a Markdown quote line). A
    warning only: such a line may be fine, so it never blocks."""
    if isinstance(data, bytes):
        data = data.decode("utf-8", "replace")
    out = []
    for n, line in enumerate(data.splitlines(), 1):
        if any(rx.search(line) for rx in _SPEECH):
            out.append(f"public-content guard: WARNING: {place}:{n} may quote someone's words "
                       "(reported speech or a quote line). Check it is not a private conversation; "
                       "this does not block.")
    return out


# --------------------------------------------------------------------------- content


_BOMS = ((b"\xff\xfe\x00\x00", "utf-32"), (b"\x00\x00\xfe\xff", "utf-32"),
         (b"\xff\xfe", "utf-16"), (b"\xfe\xff", "utf-16"))

# Printable runs of a binary, read the way `strings` reads them: 7-bit text, and the same
# characters as UTF-16 and UTF-32 (little and big endian) units. (regex, first byte, step):
# the step picks the character out of each unit. A shorter run is not read: random bytes
# hold accidental short runs that look like addresses.
_RUN = rb"[\t\x20-\x7e]"
_RUNS = tuple((re.compile(rb"(?:%s){%d,}" % (unit, MIN_RUN)), first, step) for unit, first, step in (
    (_RUN, 0, 1),
    (_RUN + rb"\x00", 0, 2),
    (rb"\x00" + _RUN, 1, 2),
    (_RUN + rb"\x00\x00\x00", 0, 4),
    (rb"\x00\x00\x00" + _RUN, 3, 4),
))


def _utf8(data: bytes) -> bool:
    try:
        data.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return True


def is_text(data: bytes) -> bool:
    """True for text: no NUL byte, or strict UTF-8 throughout."""
    return b"\0" not in data or _utf8(data)


def as_text(data: bytes) -> list[bytes]:
    """What the rules read for DATA, as one or more views. Text with a UTF-32 or UTF-16
    byte-order mark: decoded (a bad unit becomes U+FFFD) besides the other views. Text with no
    NUL byte: as it is. Anything holding a NUL (a binary file): its printable runs of MIN_RUN
    characters or more (7-bit, UTF-16 and UTF-32), plus the bytes as they are when they decode
    as strict UTF-8."""
    views = []
    for bom, enc in _BOMS:
        if data.startswith(bom):
            views.append(data.decode(enc, "replace").encode("utf-8"))
            break
    if b"\0" not in data:
        return views + [data]
    for n, (rx, first, step) in enumerate(_RUNS):
        runs = [m[first::step] for m in rx.findall(data)]
        if runs or n == 0:  # the 7-bit view always, so every file is read at least once
            views.append(b"\n".join(runs))
    if _utf8(data):
        views.append(data)
    return views


# Formats the guard has no reader for, by their leading signature. Such a file blocks: what
# is packed inside cannot be checked.
_CANNOT_OPEN = ((b"7z\xbc\xaf\x27\x1c", "a 7z archive"), (b"Rar!\x1a\x07", "a rar archive"),
                (b"\x28\xb5\x2f\xfd", "a zstd file"), (b"\x04\x22\x4d\x18", "an lz4 file"),
                (b"LZIP\x01", "an lzip file"), (b"\x1f\x9d", "a Unix compress (.Z) file"),
                (b"MSCF\x00\x00\x00\x00", "a cabinet (.cab) file"), (b"xar!\x00\x1c", "a xar archive"))
# gzip, bzip2 and xz: (signature, decoder).
_STREAMS = ((re.compile(rb"\x1f\x8b"), lambda: zlib.decompressobj(16 + zlib.MAX_WBITS)),
            (re.compile(rb"BZh[1-9](?:1AY&SY|\x17rE8P\x90)"), bz2.BZ2Decompressor),
            (re.compile(rb"\xfd7zXZ\x00"), lzma.LZMADecompressor))
_NULS = re.compile(rb"\x00*")
_PIECE = 1 << 20  # compressed bytes given to a decoder at a time


def _spend(budget: list[int], n: int) -> None:
    budget[0] -= n
    if budget[0] < 0:
        raise ScanError("an archive unpacks to more than %d MB, so it could not be checked" % (UNPACK_LIMIT >> 20))


def _decompress(data: bytes, budget: list[int]) -> bytes | None:
    """The content of a gzip, bzip2 or xz file: every stream in it, joined; None when DATA
    does not start with one's signature. Streams follow one another, with only NUL bytes
    (padding) between them and after the last; anything else after a stream, a stream of
    another format included, is a ScanError, as is a stream that cannot be read to its end.
    Each stream costs STREAM_COST of the budget besides its output, so a file of many empty
    streams is bounded too."""
    found = [(rx, make) for rx, make in _STREAMS if rx.match(data)]
    if not found:
        return None
    rx, make = found[0]
    view = memoryview(data)
    out: list[bytes] = []
    at = 0
    try:
        while True:
            _spend(budget, STREAM_COST)
            at = _one_stream(make(), view, at, out, budget)
            at = _NULS.match(data, at).end()
            if at == len(data):
                return b"".join(out)
            if not rx.match(data, at):
                raise ScanError("a compressed file has bytes after a stream that are not another stream of "
                                "its format, so it could not be checked")
    except (OSError, EOFError, ValueError, lzma.LZMAError, zlib.error):
        raise ScanError("a compressed file could not be read, so it could not be checked") from None


def _one_stream(dec, view: memoryview, at: int, out: list[bytes], budget: list[int]) -> int:
    """Decode one stream starting at AT into OUT; return where it ends. The input is given a
    piece at a time, so the bytes left over after a stream are never copied whole."""
    pos = at
    feed: bytes | memoryview = b""
    while True:
        part = dec.decompress(feed, budget[0] + 1)
        _spend(budget, len(part))
        out.append(part)
        if dec.eof:
            return pos - len(dec.unused_data)
        feed = getattr(dec, "unconsumed_tail", b"")
        if not feed and getattr(dec, "needs_input", True):
            if pos >= len(view):
                raise ScanError("a compressed file ends early, so it could not be checked")
            feed = view[pos:pos + _PIECE]
            pos += len(feed)


def unpack(data: bytes, depth: int = 1, budget: list[int] | None = None) -> list[bytes] | None:
    """The files inside DATA when it is an archive, with archives inside them unpacked in
    turn; None when DATA is not an archive. zip, tar, gzip, bzip2 and xz are read completely
    or not at all: what cannot be read to the last byte is a ScanError, as is an encrypted
    file, nesting deeper than ARCHIVE_DEPTH, more than UNPACK_LIMIT unpacked, and a file with
    the signature of a format the guard cannot open (_CANNOT_OPEN). A zip found only by its end
    record (glued after other data) counts only when it opens, best effort."""
    budget = budget if budget is not None else [UNPACK_LIMIT]
    for sig, what in _CANNOT_OPEN:
        if data.startswith(sig):
            raise ScanError(what + ", which the guard cannot open")
    files: list[bytes] | None
    inner = _decompress(data, budget)
    if inner is not None:
        files = [inner]
    elif data.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x06\x06")):
        files = _zip_walk(data, budget)
    else:
        start = _tar_start(data)
        if start is not None:
            files = _tar_walk(data, start, budget)
        elif b"PK\x05\x06" in data:
            files = _zip_files(data, budget)
        else:
            files = None
    if files is None:
        return None
    if depth > ARCHIVE_DEPTH:
        raise ScanError("an archive is nested more than %d deep, so it could not be checked" % ARCHIVE_DEPTH)
    out: list[bytes] = []
    for f in files:
        out.append(f)
        out += unpack(f, depth + 1, budget) or []
    return out


def _zip_bad(what: str) -> ScanError:
    return ScanError("a zip archive %s, so it could not be read completely" % what)


def _zip_walk(data: bytes, budget: list[int]) -> list[bytes]:
    """Every entry of a zip that starts at byte 0, read with the guard's own decoders, after
    proving that its records cover the file exactly: the entries back to back from byte 0
    (each a local header, its data and, when flag bit 3 says so, a data descriptor), then the
    central directory, then the zip64 end record and locator when present, then the one end
    record, whose comment ends the file. Any gap, overlap or other layout is a ScanError."""
    n = len(data)
    lo = max(0, n - 22 - 0xFFFF)  # the end record and its comment (at most 65535 bytes)
    ends = [lo + m.start() for m in re.finditer(rb"PK\x05\x06", data[lo:])]
    ends = [p for p in ends if p + 22 <= n and p + 22 + struct.unpack_from("<H", data, p + 20)[0] == n]
    if len(ends) != 1:
        raise _zip_bad("does not have exactly one end record ending the file")
    p = ends[0]
    disk, cd_disk, here, count, cd_size, cd_off = struct.unpack_from("<HHHHII", data, p + 4)
    cd_end = p
    if p >= 20 and data[p - 20:p - 16] == b"PK\x06\x07":
        loc_disk, z64, disks = struct.unpack_from("<IQI", data, p - 16)
        if data[z64:z64 + 4] != b"PK\x06\x06" or z64 + 56 > p - 20 or loc_disk or disks > 1:
            raise _zip_bad("has a zip64 end record the guard cannot follow")
        if z64 + 12 + struct.unpack_from("<Q", data, z64 + 4)[0] != p - 20:
            raise _zip_bad("has bytes between its zip64 end record and its locator")
        disk, cd_disk, here, count, cd_size, cd_off = struct.unpack_from("<IIQQQQ", data, z64 + 16)
        cd_end = z64
    elif 0xFFFF in (here, count) or 0xFFFFFFFF in (cd_size, cd_off):
        raise _zip_bad("says it has zip64 records but has none")
    if disk or cd_disk or here != count:
        raise _zip_bad("spans several disks")
    if cd_off + cd_size != cd_end:
        raise _zip_bad("has bytes between its central directory and its end record")
    entries = []
    at = cd_off
    for _ in range(count):
        if data[at:at + 4] != b"PK\x01\x02" or at + 46 > cd_end:
            raise _zip_bad("has a central directory the guard cannot read")
        flags, method, _t, _d, crc, csize, usize, nlen, xlen, clen = struct.unpack_from("<HHHHIIIHHH", data, at + 8)
        off = struct.unpack_from("<I", data, at + 42)[0]
        usize, csize, off = _zip64_sizes(data[at + 46 + nlen:at + 46 + nlen + xlen], usize, csize, off)
        name = data[at + 46:at + 46 + nlen]
        at += 46 + nlen + xlen + clen
        entries.append((off, flags, method, crc, csize, usize, name))
    if at != cd_end:
        raise _zip_bad("has bytes in its central directory that belong to no entry")
    entries.sort()
    files = []
    pos = 0
    for i, (off, flags, method, crc, csize, usize, name) in enumerate(entries):
        nxt = entries[i + 1][0] if i + 1 < len(entries) else cd_off
        if off != pos or data[off:off + 4] != b"PK\x03\x04" or off + 30 > nxt:
            raise _zip_bad("has a gap or an overlap between its entries")
        lflags, lmethod = struct.unpack_from("<HH", data, off + 6)
        lnlen, lxlen = struct.unpack_from("<HH", data, off + 26)
        if flags & 0x2041 or lflags & 0x41:
            raise ScanError("an archive holds an encrypted file, so it could not be checked")
        _zip_local_header(data, off, lnlen, lxlen, lflags, lmethod, (flags, method, crc, csize, usize, name))
        start = off + 30 + lnlen + lxlen
        stop = start + csize
        if flags & 0x8:
            _zip_descriptor(data[stop:nxt] if stop <= nxt else b"", crc, csize, usize)
        elif stop != nxt:
            raise _zip_bad("has a gap or an overlap between its entries")
        files.append(_zip_member(memoryview(data)[start:stop], method, crc, usize, budget))
        pos = nxt
    if pos != cd_off:
        raise _zip_bad("has bytes before its central directory that belong to no entry")
    return files


def _zip_local_header(data: bytes, off: int, lnlen: int, lxlen: int, lflags: int, lmethod: int,
                      cd: tuple[int, int, int, int, int, bytes]) -> None:
    """A local header must agree with its central directory entry, so a reader that walks the
    local headers sees the same entry: the same name, method and flag bit 3; without bit 3, the
    same CRC and sizes (0xFFFFFFFF resolved from its zip64 extra field); with bit 3 (the values
    follow in a data descriptor), each of them 0 or the directory's value (Info-ZIP writes the
    sizes it knows)."""
    flags, method, crc, csize, usize, name = cd
    lcrc, lcsize, lusize = struct.unpack_from("<III", data, off + 14)
    lusize, lcsize, _ = _zip64_sizes(data[off + 30 + lnlen:off + 30 + lnlen + lxlen], lusize, lcsize, 0)
    want = (crc, csize, usize)
    local = (lcrc, lcsize, lusize)
    agree = all(v in (0, w) for v, w in zip(local, want)) if flags & 0x8 else local == want
    if data[off + 30:off + 30 + lnlen] != name or lmethod != method or (lflags ^ flags) & 0x8 or not agree:
        raise ScanError("a zip entry's local header disagrees with its central directory, so it could not be "
                        "read completely")


def _zip64_sizes(extra: bytes, usize: int, csize: int, off: int) -> tuple[int, int, int]:
    """The sizes and offset of a central directory entry, the zip64 ones (extra field 1)
    filled in for the fields that hold 0xFFFFFFFF."""
    vals = [usize, csize, off]
    if 0xFFFFFFFF not in vals:
        return usize, csize, off
    i = 0
    while i + 4 <= len(extra):
        hid, hlen = struct.unpack_from("<HH", extra, i)
        if hid == 1:
            body, j = extra[i + 4:i + 4 + hlen], 0
            for k in range(3):
                if vals[k] == 0xFFFFFFFF:
                    if j + 8 > len(body):
                        break
                    vals[k] = struct.unpack_from("<Q", body, j)[0]
                    j += 8
            else:
                return vals[0], vals[1], vals[2]
        i += 4 + hlen
    raise _zip_bad("has an entry whose zip64 sizes are missing")


def _zip_descriptor(desc: bytes, crc: int, csize: int, usize: int) -> None:
    """A data descriptor must fill the bytes up to the next record exactly: 12 or 20 bytes
    (zip32 or zip64 sizes), or 16 or 24 with its signature, and agree with the directory."""
    if len(desc) in (16, 24):
        if desc[:4] != b"PK\x07\x08":
            raise _zip_bad("has bytes after an entry's data descriptor")
        desc = desc[4:]
    if len(desc) not in (12, 20) or struct.unpack("<III" if len(desc) == 12 else "<IQQ", desc) != (crc, csize, usize):
        raise _zip_bad("has a data descriptor that does not match its central directory")


def _zip_member(comp: memoryview, method: int, crc: int, usize: int, budget: list[int]) -> bytes:
    """One entry's content: stored, deflate or bzip2 only, decoded to its end with no input
    left over, of the recorded size and CRC-32."""
    _spend(budget, usize)
    try:
        if method == 0:
            out, done = bytes(comp), True
        elif method in (8, 12):
            dec = zlib.decompressobj(-15) if method == 8 else bz2.BZ2Decompressor()
            out = dec.decompress(comp, usize + 1)
            done = dec.eof and not dec.unused_data and not getattr(dec, "unconsumed_tail", b"")
        else:
            raise _zip_bad("uses a compression method the guard does not read (only stored, deflate and bzip2)")
    except (OSError, EOFError, ValueError, zlib.error):
        done, out = False, b""
    if not done or len(out) != usize or zlib.crc32(out) != crc:
        raise _zip_bad("has an entry that does not decode to its recorded size and CRC")
    return out


def _zip_files(data: bytes, budget: list[int]) -> list[bytes] | None:
    """The files of a zip found by its end record somewhere in DATA (glued after other data),
    read with Python's zipfile, best effort; None when it does not open."""
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
        infos = [i for i in zf.infolist() if not i.is_dir()]
    except (zipfile.BadZipFile, OSError, ValueError, EOFError):
        return None
    files = []
    for info in infos:
        if info.flag_bits & 0x1:
            raise ScanError("an archive holds an encrypted file, so it could not be checked")
        _spend(budget, info.file_size)
        try:
            files.append(zf.read(info))
        except (zipfile.BadZipFile, OSError, ValueError, EOFError, NotImplementedError, RuntimeError):
            raise ScanError("a file inside an archive could not be read, so it could not be checked") from None
    return files


def _tar_header(block: bytes) -> bool:
    """True when BLOCK is a tar header: its checksum field (octal, bytes 148-155) equals the
    unsigned or the signed byte sum of the block with that field read as 8 spaces."""
    if len(block) < 512:
        return False
    field = block[148:156].split(b"\0", 1)[0].strip(b" ")
    if not re.fullmatch(rb"[0-7]+", field):
        return False
    rest = block[:148] + b" " * 8 + block[156:512]
    total = sum(rest)
    return int(field, 8) in (total, total - 256 * sum(1 for b in rest if b > 127))


def _tar_start(data: bytes) -> int | None:
    """Where a tar starts: after whole NUL blocks, a block with a valid header checksum. None
    when there is none there (a tar is not found by `ustar` at byte 257)."""
    at = _NULS.match(data).end() // 512 * 512
    return at if _tar_header(data[at:at + 512]) else None


_TAR_EXTENSIONS = b"xXgLK"  # pax, Solaris pax, global pax, GNU long name, GNU long link target


def _tar_size(head: bytes) -> int:
    """An extension header's size field: octal, or GNU base-256 when its first byte has bit
    0x80 set."""
    field = head[124:136]
    if field[0] & 0x80:
        return int.from_bytes(bytes([field[0] & 0x7F]) + field[1:], "big")
    field = field.split(b"\0", 1)[0].strip(b" ")
    if not re.fullmatch(rb"[0-7]*", field):
        raise ScanError("a tar archive has a header with an unreadable size, so it could not be checked")
    return int(field or b"0", 8)


def _tar_record(data: bytes, at: int, files: list[bytes], budget: list[int], types: bytes = _TAR_EXTENSIONS,
                size: int | None = None) -> int:
    """Read the header record at AT and return where the next one starts. A record is a
    512-byte header with a valid checksum, its data, then NUL bytes to a 512 boundary. An
    extension header (its type in TYPES) gives its own data length; a member's main header is
    given SIZE, tarfile's resolved size (a pax record may override the header's). The data is
    added to FILES, so the text of pax records and GNU long names is checked too."""
    head = data[at:at + 512]
    if not _tar_header(head) or (size is None and head[156] not in types):
        raise ScanError("a tar archive has bytes between its members, so it could not be read completely")
    if size is None:
        size = _tar_size(head)
    stop, end = at + 512 + size, at + 512 + -(-size // 512) * 512
    if stop > len(data):
        raise ScanError("a tar archive ends inside a record, so it could not be checked")
    if data[stop:end].strip(b"\0"):
        raise ScanError("a tar archive has bytes other than NUL in a record's padding, so it could not be "
                        "read completely")
    if size:
        _spend(budget, size)
        files.append(data[at + 512:stop])
    return end


def _tar_walk(data: bytes, at: int, budget: list[int]) -> list[bytes]:
    """The files of a tar starting at AT, after proving every byte is a header record (_tar_record)
    or the archive's end: global headers between members, then each member's extension headers
    from tarfile's m.offset up to its main header at m.offset_data - 512, then the main header and
    the member's data. After the last member only NUL bytes, or, at a 512 boundary, another tar
    walked the same way. Python's tarfile resolves each member (long names, pax sizes); the
    records themselves decide completeness, because tarfile folds extension headers into a
    member and never looks at their padding."""
    files: list[bytes] = []
    while True:
        fh = io.BytesIO(data)
        fh.seek(at)
        try:
            members = tarfile.open(fileobj=fh, mode="r:").getmembers()
        except (tarfile.TarError, OSError, ValueError, EOFError, UnicodeError):
            raise ScanError("a tar archive could not be read, so it could not be checked") from None
        if not members:
            raise ScanError("a tar archive could not be read, so it could not be checked")
        end = at
        for m in members:
            while end < m.offset:
                end = _tar_record(data, end, files, budget, b"g")
            if end != m.offset:
                raise ScanError("a tar archive has bytes between its members, so it could not be read completely")
            while end < m.offset_data - 512:
                end = _tar_record(data, end, files, budget)
            if end != m.offset_data - 512:
                raise ScanError("a tar archive has bytes between its members, so it could not be read completely")
            if m.issparse():
                raise ScanError("a tar archive holds a sparse file, which the guard does not read")
            size = m.size if m.isreg() or m.type not in tarfile.SUPPORTED_TYPES else 0
            end = _tar_record(data, end, files, budget, size=size)
        at = _NULS.match(data, end).end()
        if at == len(data):
            return files
        if at % 512 or not _tar_header(data[at:at + 512]):
            raise ScanError("a tar archive has bytes after its end, so it could not be read completely")


# --------------------------------------------------------------------------- gitleaks


class UnreadableFile(ScanError):
    """A file the guard cannot read completely (an archive it cannot open, or one that cannot
    be read to its last byte). The report names the file and says what to do."""


FIX_UNREADABLE = (
    "Fix: remove it from the commits and push again; or commit its contents unpacked; or repack it "
    "as zip, tar.gz or tar.xz, which the guard reads completely; or keep it in a private repository. "
    "Do not bypass the guard with --no-verify; if this is wrong, open an issue in the guard's repository "
    "(describe it; do not paste the matched text)."
)
CANARY_ID = "pcg-canary"
_LOG_LINE = re.compile(r"^\S+ (TRC|DBG|INF|WRN|ERR|FTL|PNC) (.*)$")


class Scanner:
    """Collects chunks of content in a private (0700) temp folder, then runs gitleaks
    twice over that folder: once with the default secret rules, once with the public rules.
    Private terms are matched here in Python, which can test a term's edges without using up
    the characters around it. Two passes, not one layered config: the defaults' global
    allowlist silently drops any match containing /home/ (measured, gitleaks 8.30.1).

    Isolation: gitleaks runs with every GITLEAKS_* variable removed, an explicit --config,
    cwd and --gitleaks-ignore-path inside the temp folder, and --ignore-gitleaks-allow.
    Chunks are plain text under neutral names (see as_text and unpack), so no path allowlist
    can apply and no ignore file in the scanned content is ever read as one. The report holds
    the matched text (to check it against the allowed addresses and the masks); it stays in
    the temp folder and is never shown.

    Proof of reading: gitleaks skips a file it sniffs as a binary format (DEBUG log only) and
    returns success when a file cannot be opened. So every chunk ends with a canary line that
    only this run knows, and both passes carry a rule that matches it; a chunk counts as read
    only when its canary is reported. A chunk that was skipped or lost its canary is scanned
    once more behind RETRY_PREFIX (so no format can be sniffed); if that fails too, ScanError.

    Every path shown in a place is scanned too, whether or not that name is new in this
    change: a path a secret rule matches is never shown, and other matches are masked."""

    def __init__(self, terms: Terms) -> None:
        self.terms = terms
        self.work = Path(tempfile.mkdtemp(prefix="pcg-"))
        self.src = self.work / "chunks"
        self.src.mkdir()
        self.chunks: list[dict[str, object]] = []
        self.run_id = secrets.token_hex(8)
        # Files that could not be read completely: (place, path, reason).
        self.unreadable: list[tuple[str, str | None, str]] = []
        # Given addresses (lowercased), returns those already in use as author or committer
        # addresses (None: none). Applies on identity lines only.
        self.known: Callable[[set[str]], set[str]] | None = None

    def __enter__(self) -> Scanner:
        return self

    def __exit__(self, *_exc: object) -> None:
        shutil.rmtree(self.work, ignore_errors=True)

    def add(self, place: str, data: bytes | str, lines: bool = True, names: list[str] | None = None,
            path: str | None = None, kind: str = "content", file: bool = False) -> None:
        """place: what the report calls it (masked when shown). lines: append :LINE. names: one
        path per line of data (a file-name chunk). path: the raw path a place is built from.
        file: DATA is a file's content, so an archive is unpacked and each file in it checked;
        one that cannot be read completely blocks the run, naming the place (see run)."""
        if isinstance(data, str):
            data = data.encode("utf-8", "surrogateescape")
        for view in [data] if names is not None else as_text(data):
            self._chunk(place, view, lines, names, path, kind, False)
        if file:
            try:
                inner = unpack(data) or []
            except ScanError as exc:
                self.unreadable.append((place, path, str(exc)))
                return
            for f in inner:
                for view in as_text(f):
                    self._chunk(place, view, lines, None, path, kind, True)

    def _name(self, idx: int) -> str:
        return "c%07d" % idx

    def _canary(self, idx: int) -> str:
        return "pcg-canary-%s-%07d" % (self.run_id, idx)

    def _chunk(self, place: str, text: bytes, lines: bool, names: list[str] | None, path: str | None,
               kind: str, inside: bool) -> None:
        # The leading newline keeps gitleaks from reading the first bytes as a binary file's
        # signature; line numbers are shifted back when read. The canary line ends the chunk.
        idx = len(self.chunks)
        (self.src / self._name(idx)).write_bytes(b"\n" + text + b"\n" + self._canary(idx).encode())
        self.chunks.append({"place": place, "lines": lines, "names": names, "path": path,
                            "archive": inside, "kind": kind})

    def _text(self, idx: int) -> bytes:
        """A chunk's text, without the leading newline and the canary line."""
        raw = (self.src / self._name(idx)).read_bytes()
        return raw[1:len(raw) - 1 - len(self._canary(idx))]

    def run(self) -> list[str]:
        """The report: one line per new finding (rule and place), never the matched text. A
        file that could not be read completely is a ScanError (UnreadableFile) naming it."""
        if not self.chunks:
            return []
        shown = sorted({str(c["path"]) for c in self.chunks if c["path"] is not None})
        if shown:
            self.add("", "\n".join(p.replace("\n", "\\n") for p in shown) + "\n", names=shown, kind="display")
        raw = self.findings()
        public = _public_ids()
        withheld: set[str] = set()
        for rule, idx, line, text in raw:
            chunk = self.chunks[idx]
            names = chunk["names"]
            if not isinstance(names, list) or not 0 < line <= len(names):
                continue
            # A path is never shown when a secret rule matches it (the masks cannot mask a
            # secret), nor when masking leaves the matched text in it.
            name = names[line - 1]
            if rule not in public or not text or text in self.terms.mask(name):
                withheld.add(name)
        if self.unreadable:
            where = []
            for place, path, reason in self.unreadable:
                shown_as = "a file whose name is withheld" if path in withheld else self.terms.mask(place)
                where.append("%s: %s" % (shown_as, reason))
            raise UnreadableFile("; ".join(dict.fromkeys(where)))
        allowed = allowed_addresses()
        raw = [f for f in raw if self.chunks[f[1]]["kind"] != "display" and f[3].lower() not in allowed]
        if self.known is not None:
            ident = [f for f in raw if f[0] == "personal-email" and self.chunks[f[1]]["kind"] == "identity"]
            emails = {f[3].lower() for f in ident}
            in_use = self.known(emails) if emails else set()
            raw = [f for f in raw if not (f in ident and f[3].lower() in in_use)]
        out: list[str] = []
        for rule, idx, line, _text in raw:
            chunk = self.chunks[idx]
            names = chunk["names"]
            if isinstance(names, list):
                name = names[line - 1] if 0 < line <= len(names) else "?"
                place = "a file name (withheld)" if name in withheld else "the file name " + self.terms.mask(name)
            elif chunk["path"] is not None and chunk["path"] in withheld:
                place = "a file whose name is withheld"
            elif chunk["archive"]:
                place = self.terms.mask(str(chunk["place"])) + " (inside the archive)"
            else:
                place = self.terms.mask(str(chunk["place"])) + (":%d" % line if chunk["lines"] else "")
            item = f"{rule} at {place}"
            if item not in out:
                out.append(item)
        return out

    def findings(self) -> list[tuple[str, int, int, str]]:
        """Both gitleaks passes over every chunk added so far, then the private terms."""
        exe = shutil.which("gitleaks")
        if not exe:
            raise ScanError("gitleaks is not installed (not on PATH), so nothing could be checked")
        canary = "\n[[rules]]\nid = \"%s\"\nregex = '''pcg-canary-%s-[0-9]{7}'''\n" % (CANARY_ID, self.run_id)
        secrets_cfg = self.work / "secrets.toml"
        secrets_cfg.write_text("[extend]\nuseDefault = true\n" + canary, encoding="utf-8")
        public_cfg = self.work / "public.toml"
        public_cfg.write_text(PUBLIC_RULES.read_text(encoding="utf-8") + canary, encoding="utf-8")
        raw: list[tuple[str, int, int, str]] = []
        for n, cfg in enumerate((secrets_cfg, public_cfg)):
            raw += self._pass(exe, cfg, n)
        if self.terms.find_re is not None:
            for idx in range(len(self.chunks)):
                text = self._text(idx).decode("utf-8", "surrogateescape")
                for m in self.terms.find_re.finditer(text):
                    raw.append(("private-term", idx, text.count("\n", 0, m.start()) + 1, m.group(0)))
        return raw

    def _pass(self, exe: str, cfg: Path, n: int) -> list[tuple[str, int, int, str]]:
        """One gitleaks pass: every chunk, then the chunks it skipped or did not prove it read
        (no canary) once more, behind RETRY_PREFIX. Canary findings are removed."""
        every = set(range(len(self.chunks)))
        found, skipped = self._gitleaks(exe, cfg, self.src, "report-%d.json" % n, 0, every)
        retry = skipped | (every - self._read(found))
        out = [f for f in found if f[1] not in retry]
        if retry:
            folder = self.work / ("retry-%d" % n)
            folder.mkdir()
            for idx in sorted(retry):
                (folder / self._name(idx)).write_bytes(RETRY_PREFIX + (self.src / self._name(idx)).read_bytes())
            again, skipped = self._gitleaks(exe, cfg, folder, "retry-%d.json" % n, RETRY_PREFIX.count(b"\n"), retry)
            if skipped or retry - self._read(again):
                raise ScanError("gitleaks did not read every chunk of content, so not everything was checked")
            out += again
        marker = "pcg-canary-" + self.run_id
        return [f for f in out if f[0] != CANARY_ID and marker not in f[3]]

    def _read(self, found: list[tuple[str, int, int, str]]) -> set[int]:
        """The chunks whose own canary is among FOUND."""
        return {idx for rule, idx, _line, text in found if rule == CANARY_ID and text == self._canary(idx)}

    def _gitleaks(self, exe: str, cfg: Path, folder: Path, report_name: str, shift: int,
                  chunks: set[int]) -> tuple[list[tuple[str, int, int, str]], set[int]]:
        """(findings, skipped chunks) of gitleaks over FOLDER, which holds CHUNKS. A finding is
        (rule, chunk index, line, matched text): the rule's secret part, else the whole match;
        "" when gitleaks gave neither. SHIFT: lines put before each chunk's own lines."""
        report = self.work / report_name
        env = {k: v for k, v in os.environ.items() if not k.upper().startswith("GITLEAKS")}
        cmd = [exe, "dir", str(folder), "--config", str(cfg), "--no-banner",
               "--ignore-gitleaks-allow", "--report-format", "json", "--report-path", str(report),
               "--exit-code", "0", "--gitleaks-ignore-path", str(self.work), "--log-level", "debug"]
        try:
            r = subprocess.run(cmd, cwd=str(self.work), env=env, stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=GITLEAKS_TIMEOUT)
        except (OSError, subprocess.SubprocessError) as exc:
            raise ScanError(f"gitleaks could not run ({type(exc).__name__})") from None
        if r.returncode != 0:
            raise ScanError(f"gitleaks failed (exit {r.returncode}), so nothing was checked")
        skipped = self._log(r.stderr, chunks)
        try:
            found = json.loads(report.read_text(encoding="utf-8"))
            if not isinstance(found, list):
                raise ValueError("not a list")
            out = []
            for f in found:
                m = re.fullmatch(r"c(\d{7})", os.path.basename(str(f["File"])))
                if not m or int(m.group(1)) not in chunks:
                    raise ValueError("a finding in an unknown file")
                text = f.get("Secret") or f.get("Match") or ""
                if not isinstance(text, str):
                    raise ValueError("matched text is not a string")
                # Line 1 is the leading newline every chunk starts with.
                out.append((str(f["RuleID"]), int(m.group(1)), max(int(f.get("StartLine") or 0) - 1 - shift, 0), text))
        except (OSError, ValueError, KeyError, TypeError) as exc:
            raise ScanError(f"the gitleaks report could not be read ({type(exc).__name__})") from None
        return out, skipped

    def _log(self, stderr: bytes, chunks: set[int]) -> set[int]:
        """The chunks gitleaks' log says it skipped. Each line must be `<time> <LEVEL> <message>`;
        a warning or error other than its count of findings, a line of another shape, or a skip
        that names no chunk of this run means something was left unread: ScanError."""
        skipped = set()
        plain = re.sub(rb"\x1b\[[0-9;]*m", b"", stderr).decode("utf-8", "replace")
        for ln in plain.splitlines():
            if not ln.strip():
                continue
            m = _LOG_LINE.match(ln.strip())
            if not m:
                raise ScanError("gitleaks printed something that is not a log line (%s), so not everything "
                                "was checked" % self._unexpected(ln))
            level, message = m.groups()
            if message.startswith("skipping finding"):
                continue  # an allowlisted match (trace level in 8.30.1): the file itself was read
            if "skipping" in message.lower():
                # path= runs to the end of the line or to the next ` key=` field.
                where = re.search(r"\bpath=(.*?)(?= [A-Za-z][\w-]*=|$)", message)
                name = re.fullmatch(r"c(\d{7})", os.path.basename(where.group(1).strip())) if where else None
                if not name or int(name.group(1)) not in chunks:
                    raise ScanError("gitleaks skipped something that is not a chunk of this check")
                skipped.add(int(name.group(1)))
            elif level in ("WRN", "ERR", "FTL", "PNC") and not re.fullmatch(r"leaks found: \d+", message.strip()):
                raise ScanError("gitleaks reported a problem (%s), so not everything was checked"
                                % self._unexpected(level + " " + message))
        return skipped

    def _unexpected(self, line: str) -> str:
        """An unexpected gitleaks log line for a block message: masked, cut short, and with the
        installed and the tested gitleaks versions, since a new version's log is the usual cause."""
        shown = self.terms.mask(line.strip())[:100]
        try:
            r = subprocess.run([shutil.which("gitleaks") or "gitleaks", "version"], stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=20)
            have = r.stdout.strip() or "unknown"
        except (OSError, subprocess.SubprocessError):
            have = "unknown"
        return "it printed %r; gitleaks %s is installed, the guard is tested with %s" % (
            shown, have, TESTED_GITLEAKS)


# --------------------------------------------------------------------------- visibility


def parse_github_slug(url: str) -> str | None:
    """OWNER/REPO for a github.com URL (https, ssh://, git://, scp-style), else None."""
    u = url.strip()
    m = re.match(r"(?i)^(?:https?|ssh|git|git\+ssh|ssh\+git)://(?:[^@/]+@)?(?:www\.)?github\.com(?::\d+)?"
                 r"/+([^/\s]+)/([^/\s]+?)(?:\.git)?/*$", u)
    if not m:
        m = re.match(r"(?i)^(?:[^@/:]+@)?github\.com:/?([^/\s]+)/([^/\s]+?)(?:\.git)?/*$", u)
    if not m:
        return None
    return f"{m.group(1)}/{m.group(2)}"


_SSH_HOSTS: dict[str, str | None] = {}


def _ssh_hostname(alias: str) -> str | None:
    """The real host name of an SSH host alias, from `ssh -G` (reads the SSH config, connects
    to nothing). None when ssh is missing or fails."""
    if alias not in _SSH_HOSTS:
        found = None
        if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", alias):
            try:
                r = subprocess.run(["ssh", "-G", alias], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.DEVNULL, text=True, timeout=10)
                if r.returncode == 0:
                    for ln in r.stdout.splitlines():
                        key, _, value = ln.partition(" ")
                        if key.lower() == "hostname" and value.strip():
                            found = value.strip()
                            break
            except (OSError, subprocess.SubprocessError):
                found = None
        _SSH_HOSTS[alias] = found
    return _SSH_HOSTS[alias]


def github_slug(url: str) -> str | None:
    """OWNER/REPO when the URL reaches github.com, also through an SSH host alias."""
    slug = parse_github_slug(url)
    if slug:
        return slug
    u = url.strip()
    m = re.match(r"(?i)^(?:ssh|git\+ssh|ssh\+git)://(?:[^@/]+@)?([^/:@\s]+)(?::\d+)?/+([^/\s]+)/([^/\s]+?)(?:\.git)?/*$", u)
    if not m:
        m = re.match(r"^(?:[^@/:\s]+@)?([^/:@\s]+):/?([^/\s]+)/([^/\s]+?)(?:\.git)?/*$", u)
    if not m:
        return None
    host = _ssh_hostname(m.group(1))
    if host and host.lower() in ("github.com", "ssh.github.com"):
        return f"{m.group(2)}/{m.group(3)}"
    return None


def is_local_url(url: str) -> bool:
    """git's rule: file://, or no scheme and no `host:` before the first slash."""
    u = url.strip()
    if re.match(r"(?i)^file://", u):
        return True
    if "://" in u:
        return False
    if re.match(r"^[^/]*:", u):  # scp-style host:path
        return False
    return u != ""


def _cache_file() -> Path:
    base = os.environ.get("XDG_CACHE_HOME") or os.path.join(os.path.expanduser("~"), ".cache")
    return Path(base) / "public-content-guard" / "visibility.json"


def _cached_public(cache: dict[str, object], key: str) -> bool:
    """True only for a well-formed entry {"v": "public", "at": <epoch seconds>} whose `at` is a
    finite number in the past, less than a day ago. Anything else is a miss."""
    hit = cache.get(key)
    if not isinstance(hit, dict) or hit.get("v") != "public":
        return False
    at = hit.get("at")
    if isinstance(at, bool) or not isinstance(at, (int, float)):
        return False
    try:
        age = time.time() - float(at)
    except (OverflowError, ValueError):
        return False
    return math.isfinite(age) and 0 <= age < VISIBILITY_TTL


def known_visibility(slug: str | None, fresh: bool = False) -> str | None:
    """public, private or internal, as gh reports it; None when that cannot be learnt (no gh,
    no auth, an error, an odd answer). Only public answers are cached: a cached private answer
    would hide a repository made public since. A cache entry that cannot be read is a miss.
    fresh: ask gh even when the cache holds an answer (for a public answer that lets content
    through unscanned, since the repository may have been made private since)."""
    if not slug or not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", slug):
        return None
    key = slug.lower()
    cache_file = _cache_file()
    try:
        cache = json.loads(cache_file.read_text(encoding="utf-8"))
        if not isinstance(cache, dict):
            cache = {}
    except (OSError, ValueError):
        cache = {}
    if not fresh and _cached_public(cache, key):
        return "public"
    env = dict(os.environ, GH_HOST="github.com")
    env.pop("GH_REPO", None)
    try:
        r = subprocess.run(["gh", "api", f"repos/{slug}", "--jq", ".visibility"], env=env,
                           stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           text=True, timeout=20)
    except (OSError, subprocess.SubprocessError):
        return None
    seen = r.stdout.strip().lower()
    if r.returncode != 0 or seen not in {"public", "private", "internal"}:
        return None
    if seen == "public":
        cache = {k: v for k, v in cache.items() if _cached_public(cache, k)}
        cache[key] = {"v": "public", "at": time.time()}
        try:
            cache_file.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            tmp = cache_file.with_name(cache_file.name + ".%d" % os.getpid())
            tmp.write_text(json.dumps(cache), encoding="utf-8")
            os.replace(tmp, cache_file)
        except OSError:
            pass
    return seen


UNKNOWN_VISIBILITY: list[str] = []  # GitHub repositories gh could not answer for in this run
VISIBILITY_NOTE = (
    "public-content guard: note: the destination's visibility could not be learnt from gh (not "
    "installed, not signed in, or an error), so it was checked as a public repository. If it is "
    "private, run `gh auth status`, sign in, and push again."
)


def visibility(slug: str | None) -> str:
    """public, private or internal; anything unknown counts as public (and is remembered, so a
    block can say so)."""
    seen = known_visibility(slug)
    if seen is None and slug:
        UNKNOWN_VISIBILITY.append(slug)
    return seen or "public"


# --------------------------------------------------------------------------- git objects


def _git(args: list[str], repo: str | None = None, data: bytes | None = None, check: bool = True,
         timeout: float = 600, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[bytes]:
    cmd = ["git"] + (["-C", repo] if repo else []) + args
    try:
        r = subprocess.run(cmd, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           timeout=timeout, env=env)
    except (OSError, subprocess.SubprocessError) as exc:
        raise ScanError(f"git {args[0]} could not run ({type(exc).__name__})") from None
    if check and r.returncode != 0:
        raise ScanError(f"git {args[0]} failed (exit {r.returncode})")
    return r


def _types(repo: str | None, shas: list[str]) -> dict[str, str]:
    """sha -> object type, for the shas that exist in the local object store."""
    if not shas:
        return {}
    out = _git(["cat-file", "--batch-check=%(objectname) %(objecttype)"], repo,
               data="".join(s + "\n" for s in shas).encode()).stdout.decode()
    found = {}
    for ln in out.splitlines():
        parts = ln.split()
        if len(parts) == 2 and parts[1] != "missing":
            found[parts[0]] = parts[1]
    return found


def existing(repo: str | None, shas: list[str]) -> list[str]:
    """The shas that exist in the local object store."""
    return list(_types(repo, shas))


def _cat_objects(repo: str | None, shas: list[str]):
    """Yield (sha, type, content) for each object, streamed through one git cat-file."""
    if not shas:
        return
    with tempfile.TemporaryFile() as req:
        req.write("".join(s + "\n" for s in shas).encode())
        req.seek(0)
        cmd = ["git"] + (["-C", repo] if repo else []) + ["cat-file", "--batch"]
        try:
            proc = subprocess.Popen(cmd, stdin=req, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        except OSError as exc:
            raise ScanError(f"git cat-file could not run ({type(exc).__name__})") from None
        assert proc.stdout is not None
        try:
            for sha in shas:
                header = proc.stdout.readline().decode().split()
                if len(header) != 3:
                    raise ScanError("git cat-file returned an unexpected answer")
                body = proc.stdout.read(int(header[2]))
                proc.stdout.read(1)
                yield sha, header[1], body
        finally:
            proc.stdout.close()
            if proc.wait() != 0:
                raise ScanError("git cat-file failed")


def _message(raw: bytes) -> bytes:
    """The message of a commit or tag object (after the headers)."""
    _head, sep, msg = raw.partition(b"\n\n")
    return msg if sep else b""


def _headers(raw: bytes, name: bytes) -> list[str]:
    head = raw.partition(b"\n\n")[0]
    return [ln[len(name) + 1:].decode("utf-8", "surrogateescape").strip()
            for ln in head.split(b"\n") if ln.startswith(name + b" ")]


def _ident_name(ident: str) -> str:
    """The name of an author, committer or tagger line (`Name <address> time zone`)."""
    return ident.split("<", 1)[0].strip()


def _ident_email(ident: str) -> str:
    """The address of an author or committer line (`Name <address> time zone`)."""
    m = re.search(r"<([^<>]*)>", ident)
    return m.group(1) if m else ""


def _known_addresses(repo: str | None, negatives: list[str], addresses: set[str]) -> set[str]:
    """The addresses among ADDRESSES (lowercased) that are allowed on new commits: the
    configured user.email (git config as this run sees it), and any address already used as
    an author or committer address on the published history (NEGATIVES). The history is read
    only when some address is not the configured one."""
    wanted = {a.lower() for a in addresses if a}
    r = _git(["config", "--get", "user.email"], repo, check=False)
    allowed = {r.stdout.decode("utf-8", "surrogateescape").strip().lower()} & wanted if r.returncode == 0 else set()
    if not negatives or not wanted - allowed:
        return allowed
    log = _git(["log", "--format=%ae%n%ce", "--stdin"], repo, data="".join(n + "\n" for n in negatives).encode())
    seen = {ln.strip().lower() for ln in log.stdout.decode("utf-8", "surrogateescape").splitlines()}
    return allowed | (wanted & seen)


def _tree_entries(repo: str | None, tree: str) -> list[tuple[str, str, str]]:
    """(mode, sha, path) for every file below a tree or commit."""
    out = _git(["ls-tree", "-r", "-z", "--full-tree", tree], repo).stdout
    entries = []
    for rec in out.split(b"\0"):
        if not rec:
            continue
        meta, _, path = rec.partition(b"\t")
        mode, _kind, sha = meta.decode().split()
        entries.append((mode, sha, path.decode("utf-8", "surrogateescape")))
    return entries


def _add_object_text(sc: Scanner, what: str, body: bytes) -> None:
    """Add the text a commit or tag object publishes: its message, every author, committer
    and tagger (name and address), a tag's name, and each tag a merge commit embeds in a
    `mergetag` header, in turn."""
    sc.add("the message of " + what, _message(body))
    for role in ("author", "committer", "tagger"):
        for value in _headers(body, role.encode()):
            sc.add("the %s of %s (name)" % (role, what), _ident_name(value) + "\n", lines=False)
            sc.add("the %s of %s" % (role, what), "<%s>\n" % _ident_email(value), lines=False, kind="identity")
    for value in _headers(body, b"tag"):
        sc.add("the tag name in " + what, value + "\n", lines=False)
    for n, tag in enumerate(_mergetags(body), 1):
        _add_object_text(sc, "merged tag %d of %s" % (n, what), tag)


def _mergetags(raw: bytes) -> list[bytes]:
    """The tag objects a merge commit embeds: a `mergetag` header and its continuation lines
    (each starting with a space)."""
    out: list[bytes] = []
    cur: list[bytes] | None = None
    for ln in raw.partition(b"\n\n")[0].split(b"\n"):
        if ln.startswith(b"mergetag "):
            cur = [ln[len(b"mergetag "):]]
            out.append(b"")
        elif cur is not None and ln.startswith(b" "):
            cur.append(ln[1:])
        else:
            cur = None
        if cur is not None:
            out[-1] = b"\n".join(cur)
    return out


def _changed_files(repo: str | None, commits: list[str]) -> tuple[list[tuple[str, str]], list[str]]:
    """(blob, path) for every file COMMITS add or change, and the paths of the gitlinks
    (embedded repositories, mode 160000) they add or change: each commit against its parent,
    or, for a merge, only what differs from every parent (a merge resolution); for a root
    commit, everything. Renames are not followed, so a renamed file counts as added at its new
    path. One `git diff-tree --stdin` for all commits; its -z output is read in order: a token
    starting with `:` is an entry header and the next token its path (so a path that starts
    with `:` or looks like a sha is a path); any other token must be one of COMMITS (where that
    commit's entries begin). A commit with nothing to show prints nothing or only its sha."""
    if not commits:
        return [], []
    toks = _git(["diff-tree", "--stdin", "-r", "-c", "--root", "--no-renames", "-z"], repo,
                data="".join(c + "\n" for c in commits).encode()).stdout.split(b"\0")
    if toks and toks[-1] == b"":
        toks.pop()
    wanted = {c.encode() for c in commits}
    files: list[tuple[str, str]] = []
    links: list[str] = []
    i = 0
    while i < len(toks):
        head = toks[i]
        if not head.startswith(b":"):
            if head not in wanted:
                raise ScanError("git diff-tree returned an unexpected answer")
            i += 1
            continue
        if i + 1 >= len(toks):
            raise ScanError("git diff-tree returned an unexpected answer")
        path = toks[i + 1].decode("utf-8", "surrogateescape")
        i += 2
        # One colon per parent; then a mode per parent and the result's, the same for object
        # names, then the status letters.
        colons = len(head) - len(head.lstrip(b":"))
        fields = head[colons:].decode().split()
        if len(fields) != 2 * (colons + 1) + 1:
            raise ScanError("git diff-tree returned an unexpected answer")
        mode, sha = fields[colons], fields[2 * colons + 1]
        if _zero(sha):
            continue  # deleted
        if mode.startswith("160"):
            links.append(path)  # a gitlink: its name is published; its content is another repository's
        else:
            files.append((sha, path))
    return files, links


def _place(files: dict[str, list[str]], blob: str, path: str) -> None:
    """Record that BLOB is published at PATH (each place is reported on its own)."""
    if path not in files.setdefault(blob, []):
        files[blob].append(path)


def add_new_objects(sc: Scanner, repo: str | None, positives: list[str], negatives: list[str]) -> None:
    """Add everything a push of POSITIVES publishes beyond NEGATIVES (the destination's tips),
    whole: the text of each new commit and tag (see _add_object_text); each file a new commit
    adds or changes (see _changed_files), content and path name, even when the same content
    already exists elsewhere; and any other new file version (a blob, or a tree's files,
    pushed straight to a ref). Text already public is no reason to pass: only the allowed
    addresses, the rules' own allowlists and, on identity lines only, an address already in use
    (see _known_addresses) pass."""
    sc.known = lambda addresses: _known_addresses(repo, negatives, addresses)
    if not positives:
        return
    data = "".join(p + "\n" for p in positives) + "".join("^" + n + "\n" for n in negatives)
    listing = _git(["rev-list", "--objects", "--stdin"], repo, data=data.encode()).stdout
    paths: dict[str, str] = {}
    for line in listing.decode("utf-8", "surrogateescape").splitlines():
        sha, _, path = line.partition(" ")
        if sha:
            paths.setdefault(sha, path)
    if not paths:
        return
    types = _types(repo, list(paths))
    if len(types) != len(paths):
        raise ScanError("an object to be pushed could not be read")
    commits = [s for s in paths if types[s] == "commit"]
    tags = [s for s in paths if types[s] == "tag"]

    files: dict[str, list[str]] = {}  # blob -> every path it is published at
    names: set[str] = set()
    commit_roots: set[str] = set()
    for sha, kind, body in _cat_objects(repo, commits + tags):
        _add_object_text(sc, "%s %s" % (kind if kind == "commit" else "tag object", sha[:12]), body)
        if kind == "commit":
            commit_roots.update(_headers(body, b"tree"))
    changed, links = _changed_files(repo, commits)
    for blob, path in changed:
        _place(files, blob, path)
        names.add(path)
    names.update(links)
    # Trees pushed straight to a ref (not a commit's root): every file and name in them.
    for sha in paths:
        if types[sha] == "tree" and paths[sha] == "" and sha not in commit_roots:
            for mode, blob, path in _tree_entries(repo, sha):
                if not mode.startswith("160"):
                    _place(files, blob, path)
                names.add(path)
    # Any other new file version (a blob pushed straight to a ref): whole.
    for sha in paths:
        if types[sha] == "blob" and sha not in files:
            files[sha] = [paths[sha]]

    for blob, _kind, body in _cat_objects(repo, sorted(files)):
        for path in files[blob]:
            sc.add(path or "a blob pushed to a ref (%s)" % blob[:12], body, path=path or None, file=True)
    if names:
        ordered = sorted(names)
        sc.add("file names", "\n".join(n.replace("\n", "\\n") for n in ordered) + "\n", names=ordered)


# --------------------------------------------------------------------------- pre-push


def destination_candidates(remote: str, url: str) -> list[str]:
    """Every URL this push may reach: the raw configured pushurl(s) of the named remote
    (else its url), plus the URL git passed. git passes the url AFTER insteadOf rewriting,
    so the raw configuration is the only place the real destination may show."""
    cands: list[str] = []
    if remote in _remote_names():
        for key in ("pushurl", "url"):
            vals = _config_all(f"remote.{remote}.{key}")
            if vals:
                cands += vals
                break
    elif remote:
        cands.append(remote)
    if url:
        cands.append(url)
    return cands


def _remote_names() -> list[str]:
    return _git(["remote"], check=False).stdout.decode("utf-8", "surrogateescape").split()


def _config_all(key: str) -> list[str]:
    r = _git(["config", "--get-all", key], check=False)
    return [v for v in r.stdout.decode("utf-8", "surrogateescape").splitlines() if v.strip()]


def _private_or_local(url: str) -> bool:
    if is_local_url(url):
        return True
    slug = github_slug(url)
    return slug is not None and visibility(slug) in {"private", "internal"}


def remote_tips(target: str, strict: bool = True) -> list[str]:
    """The branch and tag tips TARGET (a URL or remote name) has, from a fresh ls-remote, all
    present locally. Tips missing here (another change merged since the last fetch) are
    fetched first. If that fetch fails: strict, ScanError (without them the whole history would
    look new); not strict, only the tips present are returned. If ls-remote itself fails, no
    tips: more is scanned (the safe direction). Remote-tracking refs are never used: they can
    be stale, for example after `git remote set-url`."""
    if not target or target.startswith("-"):
        return []
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0")
    ls = _git(["ls-remote", "--heads", "--tags", target], check=False, timeout=60, env=env)
    if ls.returncode != 0:
        return []
    tips: dict[str, str] = {}
    for ln in ls.stdout.decode("utf-8", "surrogateescape").splitlines():
        sha, _, ref = ln.partition("\t")
        if re.fullmatch(SHA_RE, sha) and ref.startswith("refs/"):
            tips.setdefault(sha, ref[:-3] if ref.endswith("^{}") else ref)
    missing = sorted(set(tips) - set(existing(None, list(tips))))
    if missing:
        refs = sorted({tips[s] for s in missing})
        r = _git(["-c", "gc.auto=0", "-c", "maintenance.auto=false", "fetch", "--quiet", "--no-tags",
                  "--no-write-fetch-head", "--no-recurse-submodules", target] + refs,
                 check=False, timeout=300, env=env)
        still = set(missing) - set(existing(None, missing))
        if strict and (r.returncode != 0 or still):
            raise ScanError("the destination has commits this clone lacks and they could not be fetched; "
                            "run git fetch, then push again")
        return sorted(set(tips) - still)
    return sorted(tips)


def public_sibling_tips(remote: str) -> list[str]:
    """Tips of every OTHER configured remote that is a PUBLIC GitHub repository (content there
    is published already, as on a fork's upstream). It counts only when every configured url
    AND the url git really fetches from (after insteadOf) name the same GitHub repository, and
    gh says now, not from the cache, that it is public. Anything else adds nothing."""
    tips: list[str] = []
    for name in _remote_names():
        if name == remote or name.startswith("-"):
            continue
        used = _git(["ls-remote", "--get-url", name], check=False).stdout.decode("utf-8", "surrogateescape").strip()
        slugs = {github_slug(u) for u in _config_all(f"remote.{name}.url") + [used]}
        slug = slugs.pop() if len(slugs) == 1 else None
        if slug and known_visibility(slug, fresh=True) == "public":
            tips += remote_tips(name, strict=False)
    return tips


def cmd_pre_push(remote: str, url: str, refs: str) -> int:
    cands = destination_candidates(remote, url)
    if cands and all(_private_or_local(c) for c in cands):
        return 0
    positives: list[str] = []
    known: list[str] = []
    ref_names: list[str] = []
    for line in refs.splitlines():
        parts = line.split()
        if len(parts) != 4:
            if line.strip():
                raise ScanError("unexpected input from git on stdin")
            continue
        _local_ref, local_sha, remote_ref, remote_sha = parts
        if _zero(local_sha):
            continue  # a delete publishes nothing
        if not re.fullmatch(SHA_RE, local_sha):
            raise ScanError("unexpected object name from git on stdin")
        positives.append(local_sha)
        ref_names.append(remote_ref)
        if re.fullmatch(SHA_RE, remote_sha) and not _zero(remote_sha):
            known.append(remote_sha)  # the destination's own value of that ref
    if not positives:
        return 0
    terms = load_terms()
    if terms.warning:
        print(terms.warning, file=sys.stderr)
    tips = remote_tips(url or remote) + public_sibling_tips(remote)
    with Scanner(terms) as sc:
        add_new_objects(sc, None, positives, existing(None, sorted(set(tips + known))))
        # Destination ref names are published too; the report says only "ref".
        sc.add("ref", "\n".join(n.replace("\n", "\\n") for n in ref_names) + "\n", lines=False)
        found = sc.run()
    if not found:
        return 0
    _report("this push would publish content that must not be public", found)
    print(FIX_PUSH, file=sys.stderr)
    if UNKNOWN_VISIBILITY:
        print(VISIBILITY_NOTE, file=sys.stderr)
    return 1


# --------------------------------------------------------------------------- CI


def _commit(repo: str, name: str, rev: str) -> str:
    """The full sha of a commit given by sha or name (HEAD, a branch); ScanError otherwise."""
    if not rev or rev.startswith("-"):
        raise ScanError(f"--{name} is not a commit")
    r = _git(["rev-parse", "--verify", "--quiet", "--end-of-options", rev + "^{commit}"], repo, check=False)
    sha = r.stdout.decode().strip()
    if r.returncode != 0 or not re.fullmatch(SHA_RE, sha):
        raise ScanError(f"--{name} is not a commit in this repository")
    return sha


def ci_exclusions(repo: str, head: str) -> list[str]:
    """The base branch's current tip (origin/$GITHUB_BASE_REF, which GitHub sets for a pull
    request) and every tag count as published, so a stale base sha does not make the base
    branch's newer content look new. Other branches do not: a PR stacked on another PR must not
    inherit that PR's content as published. A ref that contains the head never counts."""
    refs = ["refs/tags"]
    base_ref = os.environ.get("GITHUB_BASE_REF", "")
    if base_ref and not base_ref.startswith("-"):
        refs.append("refs/remotes/origin/" + base_ref)
    out = _git(["for-each-ref", "--no-contains=" + head, "--format=%(objectname)"] + refs, repo).stdout.decode()
    return sorted({ln.strip() for ln in out.splitlines() if re.fullmatch(SHA_RE, ln.strip())})


def cmd_ci(repo: str, base: str, head: str) -> int:
    base, head = _commit(repo, "base", base), _commit(repo, "head", head)
    terms = load_terms()
    if terms.warning:
        print(terms.warning, file=sys.stderr)
    missing = [k for k in ("PR_TITLE", "PR_BODY") if k not in os.environ]
    if missing:
        raise ScanError(" and ".join(missing) + " not set, so the PR text could not be checked")
    texts = (("the PR title", os.environ["PR_TITLE"]), ("the PR body", os.environ["PR_BODY"]))
    with Scanner(terms) as sc:
        for place, text in texts:
            sc.add(place, text)
        add_new_objects(sc, repo, [head], sorted({base} | set(ci_exclusions(repo, head))))
        found = sc.run()
    for place, text in texts:
        for w in speech_warnings(place, text):
            print(w, file=sys.stderr)
    listed = ALLOWED_ADDRESSES.relative_to(HERE.parent).as_posix()
    if _git(["diff", "--quiet", base + "..." + head, "--", listed], repo, check=False).returncode != 0:
        print(f"::warning title=public-content guard::this pull request changes {listed}, the addresses "
              "that are public on purpose; check that every address in it is meant to be public", file=sys.stderr)
    if not found:
        return 0
    _report("this pull request would publish content that must not be public", found)
    print("Fix: edit the PR title or body, or amend or rebase the commits, then push again. "
          "If this is a false positive, open an issue in the guard's repository (describe it; do not "
          "paste the matched text).", file=sys.stderr)
    return 1


# --------------------------------------------------------------------------- CLI


def _report(what: str, found: list[str]) -> None:
    print(f"public-content guard: {what} (matched text hidden):", file=sys.stderr)
    for item in found:
        print("  - " + item, file=sys.stderr)


def cmd_text(label: str, data: bytes) -> int:
    terms = load_terms()
    if terms.warning:
        print(terms.warning, file=sys.stderr)
    with Scanner(terms) as sc:
        sc.add(label, data, file=True)
        found = sc.run()
    # A binary's printable runs are not someone's words: no warnings from them.
    for w in speech_warnings(label, data) if is_text(data) else []:
        print(w, file=sys.stderr)
    if not found:
        return 0
    _report("found content that must not be public", found)
    return 1


def main(argv: list[str] | None = None) -> int:
    # Read the objects a push really sends: git push ignores refs/replace, so must we.
    os.environ["GIT_NO_REPLACE_OBJECTS"] = "1"
    ap = argparse.ArgumentParser(prog="scan.py", description="Public-content scanner.")
    sub = ap.add_subparsers(dest="mode", required=True)
    t = sub.add_parser("text", help="scan stdin")
    t.add_argument("--label", required=True)
    p = sub.add_parser("pre-push", help="git pre-push hook")
    p.add_argument("remote")
    p.add_argument("url", nargs="?", default="")
    c = sub.add_parser("ci", help="scan a pull request")
    c.add_argument("--repo", default=".")
    c.add_argument("--base", required=True)
    c.add_argument("--head", required=True)
    args = ap.parse_args(argv)
    try:
        if args.mode == "text":
            return cmd_text(args.label, sys.stdin.buffer.read())
        if args.mode == "pre-push":
            return cmd_pre_push(args.remote, args.url, sys.stdin.read())
        return cmd_ci(args.repo, args.base, args.head)
    except ScanError as exc:
        print(f"public-content guard: could not check this ({exc}); blocked.", file=sys.stderr)
        if isinstance(exc, UnreadableFile):
            print(FIX_UNREADABLE, file=sys.stderr)
        elif args.mode == "pre-push":
            print("Fix the cause, then push again. Do not bypass the guard with --no-verify.", file=sys.stderr)
        if args.mode == "pre-push" and UNKNOWN_VISIBILITY:
            print(VISIBILITY_NOTE, file=sys.stderr)
        return 2
    except Exception as exc:  # noqa: BLE001 - fail closed on anything unexpected
        print(f"public-content guard: internal error ({type(exc).__name__}); blocked.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
