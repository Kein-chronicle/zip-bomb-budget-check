import importlib.util
from pathlib import Path
import tempfile
import unittest
import zipfile
import subprocess
import sys
import json
import stat
import struct
import zlib
script=Path(__file__).parents[1]/'scripts/check_zip.py'
spec=importlib.util.spec_from_file_location('budget',script);mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
class ZipTests(unittest.TestCase):
    def make(self,path,name='doc.txt',body=b'hello'):
        with zipfile.ZipFile(path,'w',zipfile.ZIP_DEFLATED) as z:z.writestr(name,body)
    def test_happy(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'x.zip';self.make(p)
            self.assertEqual(mod.check_zip(p)['bytes'],5)
    def test_limits_paths_duplicates_and_crc(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'x.zip'
            for name in ['../escape','/root','a\\b','C:evil']:
                self.make(p,name)
                with self.assertRaisesRegex(ValueError,'unsafe member path'):mod.check_zip(p)
            self.make(p,body=b'a'*10000)
            with self.assertRaisesRegex(ValueError,'budget'):mod.check_zip(p,max_bytes=1000)
            with zipfile.ZipFile(p,'w') as z:
                z.writestr('x',b'12345');z.writestr('./x',b'abc')
            with self.assertRaisesRegex(ValueError,'duplicate'):mod.check_zip(p)
            with self.assertRaisesRegex(ValueError,'entry budget'):mod.check_zip(p,max_entries=1)
            with zipfile.ZipFile(p,'w') as z:
                z.writestr('Doc.txt',b'1');z.writestr('doc.TXT',b'2')
            with self.assertRaisesRegex(ValueError,'duplicate'):mod.check_zip(p)      # collide when unpacked on macOS/Windows
            with zipfile.ZipFile(p,'w',zipfile.ZIP_STORED) as z:z.writestr('x',b'unique-payload')
            p.write_bytes(p.read_bytes().replace(b'unique-payload',b'broken-payload'))
            with self.assertRaisesRegex(ValueError,'CRC mismatch'):mod.check_zip(p)
    def test_missing_is_unmeasured(self):
        with tempfile.TemporaryDirectory() as d:
            r=subprocess.run([sys.executable,str(script),str(Path(d)/'missing')],capture_output=True)
            self.assertEqual(r.returncode,3)

class LyingHeaderTests(unittest.TestCase):
    """The reason the check inflates for itself: Python's zipfile stops reading at the DECLARED size, so a header that lies hides a bomb from it."""
    def patch_sizes(self, data, fake_size, fake_crc):
        b = bytearray(data)
        lh = b.find(b'PK\x03\x04'); b[lh+14:lh+18] = struct.pack('<I', fake_crc); b[lh+22:lh+26] = struct.pack('<I', fake_size)
        cd = b.find(b'PK\x01\x02'); b[cd+16:cd+20] = struct.pack('<I', fake_crc); b[cd+24:cd+28] = struct.pack('<I', fake_size)
        return bytes(b)
    def test_directory_members_cannot_skip_validation(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)/'directory.zip'
            with zipfile.ZipFile(p, 'w', zipfile.ZIP_DEFLATED) as z: z.writestr('safe/', b'X'*1_000_000)
            p.write_bytes(self.patch_sizes(p.read_bytes(), 0, 0))
            with self.assertRaisesRegex(ValueError, 'budget'): mod.check_zip(p, max_bytes=8192)
            with zipfile.ZipFile(p, 'w') as z: z.writestr('safe/', b'')
            raw = bytearray(p.read_bytes()); raw[30:35] = b'../x/'; p.write_bytes(raw)
            with self.assertRaisesRegex(ValueError, 'local header differs'): mod.check_zip(p)
            with zipfile.ZipFile(p, 'w', zipfile.ZIP_DEFLATED) as z: z.writestr('safe/', b'')
            self.assertEqual(mod.check_zip(p)['bytes'], 0)
            with zipfile.ZipFile(p, 'w') as z: z.writestr('safe/', b'payload')
            with self.assertRaisesRegex(ValueError, 'directory member'): mod.check_zip(p)
    def test_declared_size_lie_is_caught(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'bomb.zip'
            with zipfile.ZipFile(p,'w',zipfile.ZIP_DEFLATED) as z:z.writestr('big.xml',b'0'*20_000_000)       # ~20 KB on disk, 20 MB real
            self.assertLess(p.stat().st_size, 100_000)
            p.write_bytes(self.patch_sizes(p.read_bytes(), 10, zlib.crc32(b'0'*10)))
            with zipfile.ZipFile(p) as z: self.assertEqual(z.infolist()[0].file_size, 10)                        # the header now claims 10 bytes
            with self.assertRaisesRegex(ValueError,'actual size budget exceeded'): mod.check_zip(p, max_bytes=1_000_000)
            with self.assertRaisesRegex(ValueError,'declared size differs'): mod.check_zip(p, max_bytes=100_000_000)
    def test_local_header_must_match_central_directory(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'lh.zip'
            with zipfile.ZipFile(p,'w',zipfile.ZIP_STORED) as z:z.writestr('good.txt',b'hello')
            b=bytearray(p.read_bytes()); lh=b.find(b'PK\x03\x04'); b[lh+8:lh+10]=struct.pack('<H',8); p.write_bytes(bytes(b))     # local header claims deflate
            with self.assertRaisesRegex(ValueError,'local header differs'): mod.check_zip(p)
            with zipfile.ZipFile(p,'w',zipfile.ZIP_STORED) as z:z.writestr('good.txt',b'hello')
            b=bytearray(p.read_bytes()); lh=b.find(b'PK\x03\x04'); b[lh+30:lh+38]=b'evil1234'; p.write_bytes(bytes(b))              # local header names another file
            with self.assertRaisesRegex(ValueError,'local header differs'): mod.check_zip(p)
    def test_corrupt_deflate_and_unsupported_methods(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'c.zip'
            with zipfile.ZipFile(p,'w',zipfile.ZIP_DEFLATED) as z:z.writestr('a.txt',b'hello world '*100)
            b=bytearray(p.read_bytes()); lh=b.find(b'PK\x03\x04'); b[lh+40:lh+44]=b'\xff\xff\xff\xff'; p.write_bytes(bytes(b))
            with self.assertRaisesRegex(ValueError,'corrupt deflate|CRC|truncated'): mod.check_zip(p)
            with zipfile.ZipFile(p,'w',zipfile.ZIP_BZIP2) as z:z.writestr('a.txt',b'x'*100)
            with self.assertRaisesRegex(ValueError,'unsupported compression'): mod.check_zip(p)
    def test_names_that_collide_or_are_reserved(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'n.zip'
            cases=[(('\u00e9.txt','e\u0301.txt'),'duplicate'),(('a.txt','a.txt.'),'duplicate'),(('A/b','a/B'),'duplicate'),(('CON',),'unsafe'),(('docs/NUL.txt',),'unsafe'),(('aux.xml',),'unsafe')]
            for names,why in cases:
                with zipfile.ZipFile(p,'w') as z:
                    for n in names: z.writestr(n,b'x')
                with self.assertRaisesRegex(ValueError,why, msg=repr(names)): mod.check_zip(p)
    def test_symlink_encrypted_and_empty(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'s.zip'
            with zipfile.ZipFile(p,'w') as z:
                i=zipfile.ZipInfo('link'); i.external_attr=(stat.S_IFLNK|0o777)<<16; z.writestr(i,'target')
            with self.assertRaisesRegex(ValueError,'symlink'): mod.check_zip(p)
            with zipfile.ZipFile(p,'w') as z: z.writestr('enc.txt','x')
            b=bytearray(p.read_bytes()); b[b.find(b'PK\x03\x04')+6]|=1; b[b.find(b'PK\x01\x02')+8]|=1; p.write_bytes(bytes(b))     # set the 'encrypted' flag bit in both headers
            with self.assertRaisesRegex(ValueError,'encrypted'): mod.check_zip(p)
            p.write_bytes(b'not a zip at all')
            r=subprocess.run([sys.executable,str(script),str(p)],capture_output=True,text=True)
            self.assertEqual((r.returncode,json.loads(r.stdout)['status']),(1,'rejected'))
            self.assertNotIn('Traceback',r.stderr)
    def test_streamed_budget_across_members(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'m.zip'
            with zipfile.ZipFile(p,'w',zipfile.ZIP_DEFLATED) as z:
                for i in range(5): z.writestr(f'f{i}',b'a'*400_000)
            with self.assertRaisesRegex(ValueError,'budget'): mod.check_zip(p,max_bytes=1_000_000)
            self.assertEqual(mod.check_zip(p,max_bytes=3_000_000)['bytes'],2_000_000)
unittest.main()
