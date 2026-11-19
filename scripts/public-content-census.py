"""public-content-census.py - the private-term reduction census, a check before merge.

Compares which lines a private-term matcher reports, between older builds of the guard's
scan.py and a newer one. It prints counts only: never a term, never a line. Every term is a
made-up word, and every character outside ASCII is written as an escape.

Usage (run with python3 -I -B; nothing is written):
    python3 -I -B scripts/public-content-census.py OLD_DIR [OLD_DIR ...] NEW_DIR
Each DIR holds a scan.py (for example a `git archive` copy of public-content/ at a commit, kept
outside the repository's working tree). NEW_DIR is usually this tree's public-content/.

Each class changes one thing about a line around one term (the text before the term, the text
after it, how the term is spelled, or the separators between its words). For each older build
and each class it prints: lines, found by the older build, found by the new build, found before
and clean now ("lost"), and found now and not before ("gained"). A class with lost lines must
name the decision that allows it (DECISIONS below; see docs/DECISIONS.md). A class with lost
lines and no decision is UNMAPPED, and the census exits 1: that is a blocker before merge.
"""

import importlib.util
import random
import sys
import unicodedata

SEED = 20261119
PER_CLASS = 40  # lines per class and term (each a fresh random choice from the class's pool)

# Made-up terms of every shape: one word, two words with each separator, a run of two
# separators, three words, a digit, a sharp-s word, a ligature word, a Turkish-i word, a k word,
# a word with an accented letter, and terms ending in an accented letter (precomposed,
# decomposed, and two words).
TERMS = ["acme", "acme labs", "acme-labs", "acme.labs", "acme_labs", "acme. labs", "zebra corn labs", "acme2",
         "strasse", "office", "istanbul", "kayak", "caf\u00e9 labs", "caf\u00e9", "cafe\u0301", "acme caf\u00e9"]

ASCII_LETTERS = list("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
MARKS = ["\u0301", "\u0300", "\u0316", "\u0323", "\u0302", "\u0308", "\u0331"]
INVISIBLES = ["\u200b", "\u200c", "\u200d", "\u2060", "\ufeff", "\u00ad", "\u034f", "\ufe0f", "\U000e0041"]
VISIBLE_CF = ["\u0600", "\u0601", "\u06dd", "\u070f", "\ufff9", "\U000110bd"]
ACCENTED = ["\u00e9", "\u00e8", "\u00f1", "\u00fc", "\u00e5", "\u0107", "\u0161"]
DECOMPOSED = ["e\u0301", "e\u0300", "n\u0303", "u\u0308", "a\u030a", "c\u0301", "s\u030c"]
GREEK = ["\u03b1", "\u03a9", "\u03bb", "\u03ac", "\u03b1\u0301"]
CYRILLIC = ["\u0434", "\u0416", "\u0439", "\u0438\u0306", "\u044f"]
CJK = ["\u793e", "\u4e2d", "\u3042", "\u30a2", "\u30fc"]
THAI = ["\u0e01", "\u0e01\u0e48", "\u0e14\u0e35", "\u0e46"]
ARABIC = ["\u0628", "\u0639", "\u0645"]
OTHER_DIGITS = ["\u0663", "\u0967", "\uff11"]
SYMBOLS = ["\u2122", "\u2116", "!", "\"", "(", ")", "/", ":", "#"]
ATTACHED = ["\uff9e", "\uff9f", "\u0e33", "\u0eb3"]

# (name, side, pool): text placed directly before ("left") or after ("right") the term.
CONTEXTS = [
    ("space", "both", [" "]), ("line edge", "both", [""]),
    ("ASCII letter", "both", ASCII_LETTERS), ("ASCII digit", "both", list("0123456789")),
    ("underscore", "both", ["_"]), ("hyphen", "both", ["-"]), ("full stop", "both", ["."]),
    ("ASCII letter with a mark", "both", [c + m for c in "xqz" for m in ("\u0301", "\u0316", "\u0323")]),
    ("accented letter, precomposed", "both", ACCENTED), ("accented letter, decomposed", "both", DECOMPOSED),
    ("Greek letter", "both", GREEK), ("Cyrillic letter", "both", CYRILLIC), ("CJK or Kana", "both", CJK),
    ("Thai", "both", THAI), ("Arabic letter", "both", ARABIC), ("other digit", "both", OTHER_DIGITS),
    ("symbol or punctuation", "both", SYMBOLS),
    ("combining mark", "right", MARKS), ("attached character", "right", ATTACHED),
    ("combining mark, then ASCII letter", "right", [m + c for m in MARKS for c in "xyz"]),
    ("attached character, then ASCII letter", "right", [a + c for a in ATTACHED for c in "xyz"]),
    ("ASCII letter, then attached character", "left", [c + a for a in ATTACHED for c in "xyz"]),
    ("invisible, then ASCII letter", "both", [i + c for i in INVISIBLES for c in "xyz"]),
    ("invisible, then space", "both", [i + " " for i in INVISIBLES]),
    ("visible format character", "both", VISIBLE_CF),
    ("visible format character, then ASCII letter", "both", [v + c for v in VISIBLE_CF for c in "xyz"]),
]


def spellings(term, rnd):
    """(class name, spelled term) pairs for TERM; each class gives a random choice."""
    words = [w for w in term.replace("_", " ").replace("-", " ").replace(".", " ").split(" ") if w]
    out = [("as written", term), ("upper case", term.upper()),
           ("full-width", "".join(chr(ord(c) + 0xFEE0) if "!" <= c <= "~" else c for c in term)),
           ("invisible inside", term[:2] + rnd.choice(INVISIBLES) + term[2:]),
           ("visible format character inside", term[:2] + rnd.choice(VISIBLE_CF) + term[2:]),
           ("NFD", unicodedata.normalize("NFD", term)), ("NFC", unicodedata.normalize("NFC", term)),
           ("mark on the first letter", term[0] + rnd.choice(MARKS) + term[1:]),
           ("mark on the last letter", term + rnd.choice(MARKS)),
           ("last letter precomposed with an accent", term[:-1] + unicodedata.normalize("NFC", term[-1] + "\u0301"))]
    if "ss" in term:
        out.append(("sharp s", term.replace("ss", "\u00df")))
    if "ffi" in term:
        out.append(("ligature", term.replace("ffi", "\ufb03")))
    if "i" in term:
        out += [("dotted capital I", term.upper().replace("I", "\u0130")), ("dotless i", term.replace("i", "\u0131"))]
    if "k" in term:
        out.append(("Kelvin sign", term.replace("k", "\u212a")))
    if len(words) > 1:
        def join(sep):
            return sep.join(words)
        out += [("separator: none", join("")), ("separator: one space", join(" ")),
                ("separator: one hyphen", join("-")), ("separator: one underscore", join("_")),
                ("separator: one full stop", join(".")),
                ("separator: run of two", join(rnd.choice([". ", "  ", "--", " -", "._"]))),
                ("separator: run of three", join(rnd.choice(["...", " - ", "___", ".  "]))),
                ("separator: one ellipsis or two-dot leader", join(rnd.choice(["\u2026", "\u2025"]))),
                ("separator: one wide space", join(rnd.choice(["\u3000", "\u00a0", "\u2003"]))),
                ("separator: invisible between two spaces", join(" " + rnd.choice(INVISIBLES) + " ")),
                ("separator: invisible next to one space", join(" " + rnd.choice(INVISIBLES)))]
    return out


def lines():
    """(class, term, line) for every class, from one fixed seed."""
    rnd = random.Random(SEED)
    out = []
    for term in TERMS:
        for _ in range(PER_CLASS):
            for name, side, pool in CONTEXTS:
                c = rnd.choice(pool)
                if side in ("both", "left"):
                    out.append(("before: " + name, term, "x " + c + term + " y"))
                if side in ("both", "right"):
                    out.append(("after: " + name, term, "x " + term + c + " y"))
            for name, spelled in spellings(term, rnd):
                out.append(("spelling: " + name, term, "x " + spelled + " y"))
    return out


# Each class whose lines may be found before and clean now, with the decision that allows it
# (restated in docs/DECISIONS.md and docs/public-content-guard.md).
DECISIONS = {
    "spelling: separator: run of two": "one separator between words, unless the term holds more",
    "spelling: separator: run of three": "one separator between words, unless the term holds more",
    "spelling: separator: invisible between two spaces": "invisible characters are absent, so this is two spaces",
    "spelling: visible format character inside": "every format character is removed before folding",
    "after: combining mark, then ASCII letter": "an ASCII letter after the marks that end a hit joins it",
    "after: attached character, then ASCII letter": "an ASCII letter after attached characters joins the hit",
    "before: ASCII letter with a mark": "an ASCII letter whose composed form stays ASCII joins the term",
    "after: ASCII letter with a mark": "an ASCII letter whose composed form stays ASCII joins the term",
    "before: ASCII letter, then attached character": "an attached character belongs to the letter before it",
    "before: invisible, then ASCII letter": "invisible characters are absent, so the letter joins",
    "after: invisible, then ASCII letter": "invisible characters are absent, so the letter joins",
    "before: visible format character, then ASCII letter": "format characters are removed, so the letter joins",
    "after: visible format character, then ASCII letter": "format characters are removed, so the letter joins",
}


def load(folder, n):
    spec = importlib.util.spec_from_file_location("census_scan_%d" % n, folder.rstrip("/") + "/scan.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def finder(mod, term):
    """A function: line -> True when MOD's matcher reports TERM in it."""
    t = mod.Terms([term], None)
    if hasattr(t, "find"):
        return lambda line: bool(t.find(line))
    rx = t.find_re  # the main branch's matcher (one regex; it has no find method)
    return lambda line: rx is not None and rx.search(line) is not None


def main(argv):
    if len(argv) < 2:
        print(__doc__.strip())
        return 2
    mods = [load(d, i) for i, d in enumerate(argv)]
    cases = lines()
    finders = {}
    got = {}
    for i, mod in enumerate(mods):
        for term in TERMS:
            finders[i, term] = finder(mod, term)
        got[i] = [finders[i, term](line) for _cls, term, line in cases]
    classes = sorted({cls for cls, _t, _l in cases})
    unmapped = 0
    for i in range(len(mods) - 1):
        print("== build %d (%s) -> new (%s): %d lines in %d classes, seed %d"
              % (i + 1, argv[i], argv[-1], len(cases), len(classes), SEED))
        print("%-52s %6s %6s %6s %6s %6s  %s" % ("class", "lines", "before", "now", "lost", "gained", "decision"))
        for cls in classes:
            idx = [k for k, (c, _t, _l) in enumerate(cases) if c == cls]
            before = sum(got[i][k] for k in idx)
            now = sum(got[len(mods) - 1][k] for k in idx)
            lost = sum(got[i][k] and not got[len(mods) - 1][k] for k in idx)
            gained = sum(got[len(mods) - 1][k] and not got[i][k] for k in idx)
            note = DECISIONS.get(cls, "")
            if lost and not note:
                note = "UNMAPPED"
                unmapped += 1
            if lost or gained:
                print("%-52s %6d %6d %6d %6d %6d  %s" % (cls, len(idx), before, now, lost, gained, note))
        print("total: before %d, now %d, lost %d, gained %d" % (
            sum(got[i]), sum(got[len(mods) - 1]),
            sum(a and not b for a, b in zip(got[i], got[len(mods) - 1])),
            sum(b and not a for a, b in zip(got[i], got[len(mods) - 1]))))
    if unmapped:
        print("UNMAPPED: %d class(es) lose findings with no decision (a blocker before merge)" % unmapped)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
