"""Verify all frozen source bytes. Manifest update requires reviewed source change."""
import hashlib,json,pathlib
root=pathlib.Path(__file__).resolve().parent
expected=json.loads((root/'SOURCE_SHA256.json').read_text())
if not isinstance(expected,dict) or not expected:raise SystemExit('missing source inventory')
actual={}
for folder in ['vault','scattering']:
    for p in (root/folder).rglob('*'):
        if p.is_symlink():raise SystemExit('symlink prohibited')
        if p.is_file() and p.suffix in {'.go','.py','.mjs','.mod','.sum','.c','.h','.sh'}:
            actual[p.relative_to(root).as_posix()]=hashlib.sha256(p.read_bytes()).hexdigest()
if actual!=expected:
    raise SystemExit('source drift: '+str(sorted(k for k in actual.keys()|expected.keys() if actual.get(k)!=expected.get(k))))
print('Verified',len(actual),'native lab sources')
