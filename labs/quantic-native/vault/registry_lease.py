"""Synthetic loopback registry transport. Authenticity is the pinned Ed25519 signature.
No live registry credentials. No automatic signing or lease renewal by HTTP server.
"""
import base64, json, time, urllib.request, urllib.parse, re
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
import manifest_store as ms
import pq_profile as pq
MAX=400000
TTL=30000
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*a,**k): raise ValueError('redirect refused')
def pull(url,pin,identity):
    u=urllib.parse.urlsplit(url)
    if u.scheme!='http' or u.hostname!='127.0.0.1' or u.username or u.password or u.query or u.fragment or u.path!='/lease' or not u.port: raise ValueError('loopback lab registry only')
    if not re.fullmatch('[0-9a-f]{64}',pin): raise ValueError('invalid registry key pin')
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
    with opener.open(url,timeout=1) as r: raw=r.read(MAX+1)
    return decode(raw,pin,identity)

def decode(raw,pin,identity):
    if len(raw)>MAX:raise ValueError('lease oversized')
    if not re.fullmatch('[0-9a-f]{64}',pin):raise ValueError('invalid registry key pin')
    envelope=json.loads(raw)
    if set(envelope)!= {'payload','signature'}:raise ValueError('invalid lease envelope')
    data=base64.b64decode(envelope['payload'],validate=True);sig=base64.b64decode(envelope['signature'],validate=True)
    Ed25519PublicKey.from_public_bytes(bytes.fromhex(pin)).verify(sig,b'quantic-registry-lease-lab/v1\0'+data)
    p=json.loads(data)
    if set(p) not in ({'id','issued','expires','manifest'},{'id','issued','expires','manifest','pqProfile'}) or p['id']!=identity or type(p['issued']) is not int or type(p['expires']) is not int:raise ValueError('invalid lease')
    if not 0<p['expires']-p['issued']<=TTL:raise ValueError('lease lifetime')
    fresh(p)
    return p

def fresh(p):
    now=time.time_ns()//1000000
    if not p['issued']<=now<p['expires']:raise ValueError('lease expired or future')

def apply(c,identity,p,allow_pq=False):
    fresh(p)
    row=c.execute('SELECT binding,manifest,denied FROM signed_manifest WHERE id=?',(identity,)).fetchone()
    if not row:raise ValueError('unbound')
    old=c.execute('SELECT issued,expires FROM registry_lease WHERE id=?',(identity,)).fetchone()
    if old and (p['issued']<old[0] or (p['issued']==old[0] and p['expires']!=old[1])):raise ValueError('lease rollback')
    prior=pq.read(c,identity)
    if ('pqProfile' in p or prior) and not allow_pq:raise ValueError('explicit compact PQ policy required')
    if 'pqProfile' in p and p['pqProfile'] is None:raise ValueError('null PQ profile')
    result=ms.evaluate(json.loads(row[0]),json.loads(row[1]),p['manifest'])
    ms.publish(c,identity,p['manifest'])
    profile=pq.apply(c,identity,json.loads(row[0]),p['manifest'],p.get('pqProfile'))
    if old and old[0]==p['issued'] and (bool(profile)!=bool(prior) or (profile and (profile['profileSequence'],profile['profileDigest'])!=prior[:2])):raise ValueError('same issued PQ lease conflict')
    if profile:result.update(profile)
    c.execute('INSERT INTO registry_lease VALUES (?,?,?) ON CONFLICT(id) DO UPDATE SET issued=excluded.issued,expires=excluded.expires',(identity,p['issued'],p['expires']))
    return result
