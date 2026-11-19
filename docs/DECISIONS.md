# Decisions

Decisions about how this repository's tools behave, newest first.

Rules for this file:

- Each decision is restated plainly. No one's words are quoted.
- No costs, prices or account details.
- No private term, and no part of one. Examples use made-up words.
- When a decision changes, add a new entry and say which entry it replaces. Do not edit old
  entries.

## 2026-11-18

- **Invisible characters in private-term matching.** The public-content guard removes
  invisible characters, such as a zero-width space or a zero-width joiner, from a line before
  it compares the line with the private terms. The same text with and without them gives the
  same result.
- **Terms next to accented, Greek or Cyrillic letters.** A private term written directly next
  to an accented, Greek or Cyrillic letter is reported. So is a term whose last letter carries
  a combining accent. Only an ASCII letter or digit next to a term makes it part of a longer
  word, which is not reported.
- **Both Unicode storage forms.** Text that looks the same gives the same result whether its
  accented letters are stored precomposed (one character) or as a letter followed by a
  combining accent.

## 2026-11-17

- **Separators between a term's words.** A private term's words match with nothing between
  them, or one hyphen, underscore, full stop or space. A term that is itself written with a
  longer run of these allows runs up to that length.
- **Disguised spellings.** The guard catches other spellings of a private term. It compares
  text after Unicode compatibility and case folding, so full-width letters, ligatures, other
  letter cases and words split by invisible characters match.
- **Terms next to Chinese, Japanese, Thai or Arabic letters.** A private term written directly
  next to these letters, with no space, is reported.

See [public-content-guard.md](public-content-guard.md) for how the guard applies these rules.
