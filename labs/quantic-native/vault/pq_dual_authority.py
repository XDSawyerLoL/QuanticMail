"""Offline root pin and detached ML-DSA-65 grant authorization, laboratory only.
No private key or signing API on witness. Call inside BEGIN IMMEDIATE transaction.
"""
import hashlib,re,subprocess,tempfile,pathlib
HEX=re.compile(r'[0-9a-f]{64}\Z')
# DER SubjectPublicKeyInfo: id-ml-dsa-65, absent parameters, 1952-byte public key.
PREFIX=bytes.fromhex('308207b2300b0609608648016503040312038207a100')
OPENSSL='/usr/bin/openssl'
def sha(b):return hashlib.sha256(b).hexdigest()
def root(c,identity):
    if not c.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='pq_dual_root'").fetchone():return None
    return c.execute('SELECT pin,public FROM pq_dual_root WHERE id=?',(identity,)).fetchone()
def staged(c,identity):
    return c.execute('SELECT sequence,digest,signature FROM pq_dual_proof WHERE id=?',(identity,)).fetchone()
def install(c,identity,public,expected_pin):
    if not isinstance(identity,str) or not HEX.fullmatch(identity) or not isinstance(expected_pin,str) or not HEX.fullmatch(expected_pin):raise ValueError('invalid pins')
    if not isinstance(public,bytes) or len(public)!=1974 or not public.startswith(PREFIX) or sha(public)!=expected_pin:raise ValueError('invalid ML-DSA-65 root')
    if not c.execute('SELECT id FROM signed_manifest WHERE id=?',(identity,)).fetchone():raise ValueError('unknown bound identity')
    if root(c,identity):raise ValueError('root already pinned; replacement prohibited')
    import pq_profile as pp
    if pp.read(c,identity):raise ValueError('existing PQ enrollment needs separate migration')
    c.execute('CREATE TABLE IF NOT EXISTS pq_dual_root(id TEXT PRIMARY KEY,pin TEXT NOT NULL,public BLOB NOT NULL)')
    c.execute('CREATE TABLE IF NOT EXISTS pq_dual_proof(id TEXT PRIMARY KEY,sequence INTEGER NOT NULL,digest TEXT NOT NULL,signature BLOB NOT NULL)')
    c.execute('INSERT INTO pq_dual_root VALUES (?,?,?)',(identity,expected_pin,public))
def message(identity,canonical):
    return b'quantic-pq-dual-authority-lab/v1\0'+bytes.fromhex(identity)+canonical
def verify(public,identity,canonical,signature):
    if len(public)!=1974 or not public.startswith(PREFIX) or not isinstance(signature,bytes) or len(signature)!=3309:raise ValueError('invalid root proof')
    with tempfile.TemporaryDirectory(prefix='quantic-public-proof-') as d:
        d=pathlib.Path(d);(d/'pub').write_bytes(public);(d/'sig').write_bytes(signature);(d/'data').write_bytes(message(identity,canonical))
        r=subprocess.run([OPENSSL,'pkeyutl','-verify','-pubin','-inkey',str(d/'pub'),'-keyform','DER','-rawin','-in',str(d/'data'),'-sigfile',str(d/'sig')],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=2)
        if r.returncode:raise ValueError('ML-DSA root signature refused')
def stage(c,identity,binding,manifest,grant,signature):
    import pq_profile as pp
    r=root(c,identity)
    if not r:raise ValueError('root pin required')
    seq,_,pin,active=pp.verify(binding,manifest,grant)
    current=pp.read(c,identity)
    if current and (seq<current[0] or pin!=current[2] or (current[3] and active)):raise ValueError('PQ binding changed or revoked')
    canonical=pp.canonical(grant['payload']);digest=sha(canonical)
    old=staged(c,identity)
    if old and (seq<old[0] or (seq==old[0] and digest!=old[1])):raise ValueError('detached proof rollback or fork')
    verify(r[1],identity,canonical,signature)
    c.execute('INSERT INTO pq_dual_proof VALUES (?,?,?,?) ON CONFLICT(id) DO UPDATE SET sequence=excluded.sequence,digest=excluded.digest,signature=excluded.signature',(identity,seq,digest,signature))
def require(c,identity,grant):
    r=root(c,identity)
    if not r:return None
    if not grant:raise ValueError('dual authority requires PQ grant')
    import pq_profile as pp
    p=grant['payload'];canonical=pp.canonical(p);s=staged(c,identity)
    if not s or s[:2]!=(p['sequence'],sha(canonical)):raise ValueError('detached proof absent or divergent')
    if sha(r[1])!=r[0]:raise ValueError('root pin mismatch')
    verify(r[1],identity,canonical,s[2])
    return combined_digest(r[0],s[1])
def combined_digest(pin,digest):return sha(b'quantic-pq-dual-vote-lab/v1\0'+bytes.fromhex(pin)+bytes.fromhex(digest))
def check_vote(c,identity,old):
    r=root(c,identity)
    if not r:return
    s=staged(c,identity)
    if not old or not s or old[:2]!=(s[0],combined_digest(r[0],s[1])):raise ValueError('dual authority absent or newer proof staged')
