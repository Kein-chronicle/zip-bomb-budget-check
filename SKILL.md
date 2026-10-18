---
name: zip-budget-check
description: Check ZIP paths, duplicate members and expansion budgets without extracting, by inflating each member itself (declared sizes can lie). Use before parsing untrusted compressed office documents or imported project archives.
---

# ZIP budget check

1. Choose compressed/expanded byte and entry budgets for the application. Defaults: 40 MiB and 5000 entries.
2. Run `python3 scripts/check_zip.py input.zip --max-bytes 41943040 --max-entries 5000` from this skill directory. Requires Python 3.10+ stdlib only.
3. Read JSON output. Exit 0 means within the configured ZIP budget; 1 rejects (with a fixed reason such as `unsafe member path`, `duplicate member`, `actual size budget exceeded`, `declared size differs from the real size`, `CRC mismatch`, `unsupported compression method`); 3 means the input could not be read. Never interpret 3 as a pass.
   Only stored and deflate members are supported (what Office documents use); other methods are rejected rather than trusted. Duplicate detection is case-, Unicode- and trailing-dot-insensitive, and Windows reserved names (CON, NUL, COM1...) are unsafe paths.
4. Continue to the format parser only after success. Keep the original bytes immutable between checking and parsing.
5. Run `python3 tests/run.py` to verify valid ZIP, oversized expansion, traversal, duplicates, corrupt deflate, a header that lies about its size, symlinks, encrypted members and missing-file behavior.

This does not extract files, inspect macros, prove a document safe, or validate XML semantics. Nested archives are not recursively checked. The library opens one file handle, checks compressed size, validates central metadata, then streams members under a total budget. Execute in a process with a wall-time/memory limit for hostile inputs; metadata parsing and decompression still consume resources. It is a conservative preflight, not a sandbox.

Directory entries receive the same local-header, inflation, CRC and byte-budget checks as files; nonempty directory payloads are rejected.
