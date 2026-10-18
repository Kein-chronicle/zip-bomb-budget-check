# zip-bomb-budget-check

**Check an untrusted ZIP (including .docx/.xlsx/.pptx) against size and entry budgets without extracting it: zip bombs, path traversal, duplicates, bad CRC.**

[![test](https://github.com/Kein-chronicle/zip-bomb-budget-check/actions/workflows/test.yml/badge.svg)](https://github.com/Kein-chronicle/zip-bomb-budget-check/actions/workflows/test.yml) ![license](https://img.shields.io/badge/license-MIT-blue.svg) ![dependencies](https://img.shields.io/badge/dependencies-none-brightgreen.svg)

## Why

Office files are ZIPs, and the sizes a ZIP declares can lie. Python's zipfile stops reading at the declared size, so a header that claims 10 bytes can hide a stream that inflates to gigabytes. This tool inflates every member itself under a running byte budget (at most 64 KB of output per step), so a small file that expands hugely is rejected before your parser sees it.

## Install

**As a Claude Code skill** (Claude uses it when the task matches the skill description):

```sh
git clone https://github.com/Kein-chronicle/zip-bomb-budget-check.git ~/.claude/skills/zip-budget-check
```

For a single project, clone into `<project>/.claude/skills/zip-budget-check` instead, then start a new Claude Code session.

**As plain scripts:**

```sh
git clone https://github.com/Kein-chronicle/zip-bomb-budget-check.git
cd zip-bomb-budget-check
```

**Requires:** Python 3.10+.

## Quick start

Check archives, including one whose header lies about its size:

```console
$ bash examples/demo.sh
# Default budget: 40 MiB expanded, 5000 entries. Nothing is ever extracted.
$ python3 scripts/check_zip.py .demo-tmp/ok.zip
{"entries": 2, "bytes": 24, "status": "within-budget"}
[exit 0]

$ python3 scripts/check_zip.py .demo-tmp/bomb.zip
{"status": "rejected", "reason": "declared size budget exceeded"}
[exit 1]

$ python3 scripts/check_zip.py .demo-tmp/traversal.zip
{"status": "rejected", "reason": "unsafe member path"}
[exit 1]

$ python3 scripts/check_zip.py .demo-tmp/dupes.zip
{"status": "rejected", "reason": "duplicate member"}
[exit 1]

$ python3 scripts/check_zip.py .demo-tmp/not-a-zip.zip
{"status": "rejected", "reason": "corrupt or unsupported archive"}
[exit 1]

# A header that lies about its size (says 10 bytes, really inflates to 20 MB) is caught by inflating for real
$ python3 scripts/check_zip.py .demo-tmp/liar.zip --max-bytes 1000000
{"status": "rejected", "reason": "actual size budget exceeded"}
[exit 1]

# Unreadable input is 'unmeasured' (3), never a pass
$ python3 scripts/check_zip.py .demo-tmp/missing.zip
{"status": "unmeasured", "reason": "file unavailable"}
[exit 3]
```

The output above is real: it is produced by the files in `examples/`.

## Use it on your own files

```sh
python3 scripts/check_zip.py upload.docx --max-bytes 41943040 --max-entries 5000
```

Sample inputs for every file format are in `examples/` and `tests/`; the details are in [SKILL.md](SKILL.md).

## What it checks

- `check_zip.py input.zip [--max-bytes N] [--max-entries N]` prints JSON. Exit `0` within budget, `1` rejected (with a fixed reason), `3` could not read the file (never a pass).
- Rejects: compressed size over budget, too many entries, unsafe member paths (`..`, absolute, backslash, drive letter, Windows reserved names), duplicate members (case-, Unicode- and trailing-dot-insensitive), encrypted members, symlinks, declared size over budget, real inflated size over budget, real size or CRC-32 different from the header, corrupt or truncated deflate data, any compression other than stored/deflate.
- As a library: `check_zip(path, max_bytes, max_entries)` returns a dict or raises `ValueError` with the same fixed reasons; a damaged central directory raises `zipfile.BadZipFile`, a missing file `OSError`. Python 3.10+ standard library only.

## Limits

- Does not extract, scan macros, prove a document safe or recurse into nested archives.
- Keep the file unchanged between checking and parsing.
- Only stored and deflate members are accepted.

## Related projects

These solve neighbouring problems; use them when they fit better.

- **Python `zipfile`**: no built-in size limits and it trusts declared sizes; this adds limits and inflates for real

## More from the same collection

Small, tested tools that grew out of running AI agents and game/app pipelines for months:

- [**pdf-page-range-parser**](https://github.com/Kein-chronicle/pdf-page-range-parser): Parse "1-3, 5, 8-" page selections into exact ranges without silently sorting or deduplicating, and reject anything ambiguous.
- [**pdf-annotation-rotation**](https://github.com/Kein-chronicle/pdf-annotation-rotation): Rotate PDF/canvas annotations (boxes, lines, ink, source masks) a quarter turn in display coordinates, without mutating the input.
- [**pdf-text-position-table-extract**](https://github.com/Kein-chronicle/pdf-text-position-table-extract): Rebuild a rectangular table from positioned text fragments (x, baseline, size, text), keeping empty cells in place.

## Development

```sh
python3 tests/run.py
```

The tests include inputs that are supposed to be rejected, so a green run also shows the checks can fail. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT. See [LICENSE](LICENSE).

If this saved you a debugging session, a star helps other people find it. Bug reports and failing test cases are even better.

<sub>Keywords: security, zip, zip-bomb, path-traversal, docx, python, file-upload, zero-dependencies</sub>
