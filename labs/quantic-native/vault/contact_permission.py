"""Dual-root signed contact permissions for one vault, laboratory only.
Local operator stages signed grants at independent witnesses; never signs here.
"""
import base64,hashlib,json,time,re
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives import hashes
import pq_dual_authority as dual
HEX=re.compile('[0-9a-f]{64}')
def digest(b):return hashlib.sha256(b).hexdigest()
def canonical(p):
    return json.dumps(['quantic-contact-permission-lab/v1',p['contactId'],p['commitment'],p['sequence'],p['issued'],p['expires'],p['active']],separators=(',',':')).encode()
def stage(c,identity,grant):
    if not isinstance(grant,dict) or set(grant)!= {'payload','classicalSignature','pqSignature'}:raise ValueError('invalid permission')
    p=grant['payload']
    if not isinstance(p,dict) or set(p)!= {'contactId','commitment','sequence','issued','expires','active'}:raise ValueError('invalid payload')
    if not all(isinstance(p[k],str) and HEX.fullmatch(p[k]) for k in ('contactId','commitment')) or any(type(p[k]) is not int for k in ('sequence','issued','expires')) or type(p['active']) is not bool:raise ValueError('invalid fields')
    now=time.time_ns()//1000000
    if not 1<=p['sequence']<=9007199254740991 or not p['issued']<=now<p['expires'] or not 0<p['expires']-p['issued']<=86400000:raise ValueError('permission time')
    root=dual.root(c,identity)
    row=c.execute('SELECT manifest FROM signed_manifest WHERE id=?',(identity,)).fetchone()
    if not root or not row or dual.sha(root[1])!=root[0]:raise ValueError('unbound roots')
    point=json.loads(row[0])['payload']['identitySigningPublicKey']
    def dec(s):return base64.urlsafe_b64decode(s+'='*(-len(s)%4))
    key=ec.EllipticCurvePublicNumbers(int.from_bytes(dec(point['x']),'big'),int.from_bytes(dec(point['y']),'big'),ec.SECP256R1()).public_key()
    raw=canonical(p);sig=base64.b64decode(grant['classicalSignature'],validate=True)
    if len(sig)!=64:raise ValueError('invalid signature')
    key.verify(encode_dss_signature(int.from_bytes(sig[:32],'big'),int.from_bytes(sig[32:],'big')),dual.message(identity,raw),ec.ECDSA(hashes.SHA256()))
    dual.verify(root[1],identity,raw,base64.b64decode(grant['pqSignature'],validate=True))
    c.execute('CREATE TABLE IF NOT EXISTS contact_permission(id TEXT NOT NULL, contact TEXT NOT NULL, commitment TEXT NOT NULL, seq INTEGER NOT NULL, issued INTEGER NOT NULL, expires INTEGER NOT NULL, denied INTEGER NOT NULL, payload_digest TEXT NOT NULL, PRIMARY KEY(id,contact))')
    old=c.execute('SELECT commitment,seq,issued,denied,payload_digest FROM contact_permission WHERE id=? AND contact=?',(identity,p['contactId'])).fetchone()
    if old and (p['commitment']!=old[0] or p['sequence']<old[1] or p['issued']<old[2] or (old[3] and p['active']) or (p['sequence']==old[1] and digest(raw)!=old[4])):raise ValueError('contact rollback, replacement or reactivation')
    c.execute('INSERT INTO contact_permission VALUES (?,?,?,?,?,?,?,?) ON CONFLICT(id,contact) DO UPDATE SET seq=excluded.seq,issued=excluded.issued,expires=excluded.expires,denied=excluded.denied,payload_digest=excluded.payload_digest',(identity,p['contactId'],p['commitment'],p['sequence'],p['issued'],p['expires'],int(not p['active']),digest(raw)))
def require(c,identity,contact,commitment):
    row=c.execute('SELECT commitment,issued,expires,denied FROM contact_permission WHERE id=? AND contact=?',(identity,contact)).fetchone()
    now=time.time_ns()//1000000
    if not row or row[0]!=commitment or not row[1]<=now<row[2] or row[3]:raise ValueError('contact authorization refused')
    return commitment
if __name__=='__main__':
    import argparse,os,stat
    from contextlib import closing
    from anchor_server import connection
    a=argparse.ArgumentParser();a.add_argument('db');a.add_argument('identity');a.add_argument('grant');v=a.parse_args()
    info=os.lstat(v.db)
    if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or info.st_mode&0o077:raise ValueError('private DB required')
    with open(v.grant,'rb') as f:raw=f.read(16385)
    if len(raw)>16384:raise ValueError('grant too large')
    with closing(connection(v.db)) as c,c:
        c.execute('BEGIN IMMEDIATE');stage(c,v.identity,json.loads(raw))
