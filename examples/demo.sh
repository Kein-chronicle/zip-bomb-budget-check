#!/usr/bin/env bash
cd "$(dirname "$0")/.."
run() { printf '$ %s\n' "$*"; "$@"; printf '[exit %s]\n\n' "$?"; }
tmp=.demo-tmp; rm -rf "$tmp"; mkdir "$tmp"; trap 'rm -rf "$tmp"' EXIT
python3 -W ignore - "$tmp" <<'PY'
import sys, zipfile
d = sys.argv[1]
with zipfile.ZipFile(d + "/ok.zip", "w", zipfile.ZIP_DEFLATED) as z: z.writestr("word/document.xml", "<doc>hello</doc>"); z.writestr("[Content_Types].xml", "<types/>")
with zipfile.ZipFile(d + "/bomb.zip", "w", zipfile.ZIP_DEFLATED) as z: z.writestr("big.xml", "0" * 50_000_000)       # ~50 KB on disk, 50 MB expanded
with zipfile.ZipFile(d + "/traversal.zip", "w") as z: z.writestr("../../etc/evil", "x")
with zipfile.ZipFile(d + "/dupes.zip", "w") as z: z.writestr("a.txt", "one"); z.writestr("a.txt", "two")
open(d + "/not-a-zip.zip", "wb").write(b"PK\x03\x04 truncated")
import struct, zlib
with zipfile.ZipFile(d + "/liar.zip", "w", zipfile.ZIP_DEFLATED) as z: z.writestr("big.xml", "0" * 20_000_000)    # then the headers are rewritten to claim "10 bytes"
b = bytearray(open(d + "/liar.zip", "rb").read()); crc = struct.pack("<I", zlib.crc32(b"0" * 10))
lh = b.find(b"PK\x03\x04"); b[lh+14:lh+18] = crc; b[lh+22:lh+26] = struct.pack("<I", 10)
cd = b.find(b"PK\x01\x02"); b[cd+16:cd+20] = crc; b[cd+24:cd+28] = struct.pack("<I", 10)
open(d + "/liar.zip", "wb").write(bytes(b))
PY
echo "# Default budget: 40 MiB expanded, 5000 entries. Nothing is ever extracted."
run python3 scripts/check_zip.py "$tmp/ok.zip"
run python3 scripts/check_zip.py "$tmp/bomb.zip"
run python3 scripts/check_zip.py "$tmp/traversal.zip"
run python3 scripts/check_zip.py "$tmp/dupes.zip"
run python3 scripts/check_zip.py "$tmp/not-a-zip.zip"
echo "# A header that lies about its size (says 10 bytes, really inflates to 20 MB) is caught by inflating for real"
run python3 scripts/check_zip.py "$tmp/liar.zip" --max-bytes 1000000
echo "# Unreadable input is 'unmeasured' (3), never a pass"
run python3 scripts/check_zip.py "$tmp/missing.zip"
