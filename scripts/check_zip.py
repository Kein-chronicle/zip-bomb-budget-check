#!/usr/bin/env python3
"""Inspect an untrusted ZIP without extracting it, and measure what it REALLY expands to instead of trusting the sizes it declares.
usage: check_zip.py archive.zip [--max-bytes N] [--max-entries N]
exit 0 within budget | 1 rejected (JSON reason) | 3 file could not be read (never a pass)
Checks: compressed size, entry count, unsafe member paths (.., absolute, backslash, drive letter, Windows reserved names), duplicate members (case-,
Unicode- and trailing-dot-insensitive: they collide when unpacked on macOS/Windows), encrypted members, symlinks, declared size budget, and then an independent
inflate of every member's raw data under a running byte budget; the real size and CRC-32 must equal what the headers declare.
Supported compression: stored and deflate (what Office documents use). Anything else is rejected, not trusted."""
import argparse
import json
from pathlib import PurePosixPath
import stat
import struct
import sys
import unicodedata
import zipfile
import zlib

RESERVED = {"con", "prn", "aux", "nul", *(f"com{i}" for i in range(1, 10)), *(f"lpt{i}" for i in range(1, 10))}
CHUNK = 65536


def canonical(name):
    parts = []
    for part in PurePosixPath(unicodedata.normalize("NFC", name)).parts:
        parts.append(part.rstrip(". ").casefold())          # Windows ignores trailing dots and spaces
    return "/".join(parts)


def unsafe_path(name):
    if '\\' in name or ':' in name or name.startswith('/') or '\x00' in name or '..' in PurePosixPath(name).parts:
        return True
    return any(p.rstrip(". ").split(".")[0].casefold() in RESERVED for p in PurePosixPath(name).parts)


def real_size(raw, info, budget_left):
    """Inflate one member's raw bytes ourselves. Returns (size, crc). Raises ValueError when it exceeds budget_left or is corrupt."""
    raw.seek(info.header_offset)
    head = raw.read(30)
    if len(head) < 30 or head[:4] != b"PK\x03\x04": raise ValueError('corrupt local header')
    flags, method = struct.unpack("<HH", head[6:10]); name_len, extra_len = struct.unpack("<HH", head[26:30])
    raw_name = raw.read(name_len)
    local_name = raw_name.decode("utf-8" if flags & 0x800 else "cp437", errors="replace")
    # An extractor may trust the LOCAL header while this check read the CENTRAL directory: they must say the same thing.
    if method != info.compress_type or (flags & 0x1) != (info.flag_bits & 0x1) or local_name != info.orig_filename:
        raise ValueError('local header differs from the central directory')
    raw.seek(info.header_offset + 30 + name_len + extra_len)
    left = info.compress_size; size = 0; crc = 0
    if info.compress_type == zipfile.ZIP_STORED:
        while left:
            block = raw.read(min(CHUNK, left))
            if not block: raise ValueError('truncated member')
            left -= len(block); size += len(block); crc = zlib.crc32(block, crc)
            if size > budget_left: raise ValueError('actual size budget exceeded')
        return size, crc
    if info.compress_type != zipfile.ZIP_DEFLATED: raise ValueError('unsupported compression method')
    d = zlib.decompressobj(-15)
    try:
        while left or d.unconsumed_tail:
            if d.unconsumed_tail: data = d.unconsumed_tail
            else:
                data = raw.read(min(CHUNK, left))
                if not data: raise ValueError('truncated member')
                left -= len(data)
            out = d.decompress(data, CHUNK)                    # at most CHUNK bytes out per step: a bomb cannot allocate more than that at once
            size += len(out); crc = zlib.crc32(out, crc)
            if size > budget_left: raise ValueError('actual size budget exceeded')
        while True:                                            # drain output that was held back by the per-step limit
            out = d.decompress(b"", CHUNK)
            if not out: break
            size += len(out); crc = zlib.crc32(out, crc)
            if size > budget_left: raise ValueError('actual size budget exceeded')
    except zlib.error:
        raise ValueError('corrupt deflate stream')
    if not d.eof: raise ValueError('truncated deflate stream')
    return size, crc


def check_zip(path, max_bytes=40*1024*1024, max_entries=5000):
    if type(max_bytes) is not int or type(max_entries) is not int or min(max_bytes,max_entries)<1:
        raise ValueError('positive integer limits required')
    # Metadata parsing happens before member limits; bound the compressed file too.
    with open(path, 'rb') as raw:
        raw.seek(0, 2)
        if raw.tell()>max_bytes: raise ValueError('compressed size budget exceeded')
        raw.seek(0)
        with zipfile.ZipFile(raw) as z:
            entries=z.infolist()
            if not entries or len(entries)>max_entries: raise ValueError('entry budget or empty archive')
            seen=set(); declared=0
            for info in entries:
                name=info.filename
                if unsafe_path(name): raise ValueError('unsafe member path')
                key=canonical(name)
                if key in seen: raise ValueError('duplicate member')
                seen.add(key)
                if info.flag_bits&1: raise ValueError('encrypted member')
                if stat.S_ISLNK(info.external_attr>>16): raise ValueError('symlink member')
                declared+=info.file_size
                if declared>max_bytes: raise ValueError('declared size budget exceeded')
            actual=0
            for info in entries:
                size, crc = real_size(raw, info, max_bytes-actual)
                if info.is_dir() and size: raise ValueError('directory member has a payload')
                if size != info.file_size: raise ValueError('declared size differs from the real size')
                if crc & 0xFFFFFFFF != info.CRC: raise ValueError('CRC mismatch')
                actual += size
            return {'entries':len(entries),'bytes':actual,'status':'within-budget'}

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('archive'); parser.add_argument('--max-bytes',type=int,default=40*1024*1024)
    parser.add_argument('--max-entries',type=int,default=5000)
    args=parser.parse_args()
    try: print(json.dumps(check_zip(args.archive,args.max_bytes,args.max_entries)))
    except OSError:
        print(json.dumps({'status':'unmeasured','reason':'file unavailable'}));sys.exit(3)
    except ValueError as e:
        # messages are fixed strings (never member names or paths), so they are safe to show
        print(json.dumps({'status':'rejected','reason':str(e)}));sys.exit(1)
    except Exception:       # BadZipFile, struct.error, EOFError, NotImplementedError, RuntimeError ...: a malformed archive is rejected, never a traceback
        print(json.dumps({'status':'rejected','reason':'corrupt or unsupported archive'}));sys.exit(1)
