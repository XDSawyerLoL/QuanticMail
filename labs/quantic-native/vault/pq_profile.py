"""Root-signed compact PQ authorization (lab). No private PQ keys in the registry."""
import base64,hashlib,json,re
import pq_dual_authority as dual
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives import hashes
HEX=re.compile(r'^[0-9a-f]{64}$')
FIELDS=('address','deviceId','kemPin','dsaPin','sequence','active')
def key_binding(p):
    return hashlib.sha256(('quantic-pq-key-binding-lab/v1\0'+p['address']+'\0'+p['deviceId']+'\0'+p['kemPin']+p['dsaPin']).encode()).hexdigest()
def canonical(p):
    return json.dumps(['quantic-pq-profile-lab/v1']+[p[x] for x in FIELDS],separators=(',',':'),ensure_ascii=True).encode()
def verify(binding,manifest,grant):
    if not isinstance(grant,dict) or set(grant)!= {'payload','signature'}:raise ValueError('PQ grant required')
    p=grant['payload']
    if not isinstance(p,dict) or set(p)!=set(FIELDS) or p['address']!=binding['address'] or p['deviceId']!=binding['deviceId'] or type(p['sequence']) is not int or not 1<=p['sequence']<=2**53-1 or type(p['active']) is not bool or not all(isinstance(p[x],str) and HEX.fullmatch(p[x]) for x in ('kemPin','dsaPin')):raise ValueError('invalid PQ grant')
    def b64u(s):return base64.urlsafe_b64decode(s+'='*((-len(s))%4))
    root=manifest['payload']['identitySigningPublicKey'];pub=ec.EllipticCurvePublicNumbers(int.from_bytes(b64u(root['x']),'big'),int.from_bytes(b64u(root['y']),'big'),ec.SECP256R1()).public_key()
    sig=base64.b64decode(grant['signature'],validate=True)
    if len(sig)!=64 or base64.b64encode(sig).decode()!=grant['signature']:raise ValueError('invalid signature')
    pub.verify(encode_dss_signature(int.from_bytes(sig[:32],'big'),int.from_bytes(sig[32:],'big')),canonical(p),ec.ECDSA(hashes.SHA256()))
    return p['sequence'],hashlib.sha256(canonical(p)).hexdigest(),key_binding(p),p['active']
def read(c,identity):
    if not c.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='pq_profile'").fetchone():return None
    return c.execute('SELECT sequence,digest,binding,denied FROM pq_profile WHERE id=?',(identity,)).fetchone()
def apply(c,identity,binding,manifest,grant):
    old=read(c,identity)
    if grant is None:
        if dual.root(c,identity):raise ValueError('dual authority cannot be omitted')
        if old:raise ValueError('PQ policy cannot be omitted')
        return None
    seq,digest,pin,active=verify(binding,manifest,grant)
    digest=dual.require(c,identity,grant) or digest
    if old:
        if seq<old[0] or (seq==old[0] and digest!=old[1]):raise ValueError('PQ rollback or fork')
        # No replacement under same device ID. Revocation is permanent for this journal.
        if old[2]!=pin or (old[3] and active):raise ValueError('PQ binding changed or revoked')
    c.execute('CREATE TABLE IF NOT EXISTS pq_profile (id TEXT PRIMARY KEY, sequence INTEGER NOT NULL, digest TEXT NOT NULL, binding TEXT NOT NULL, denied INTEGER NOT NULL CHECK(denied IN (0,1)))')
    c.execute('INSERT INTO pq_profile VALUES (?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET sequence=excluded.sequence,digest=excluded.digest,denied=excluded.denied',(identity,seq,digest,pin,int(not active)))
    return dict(profileSequence=seq,profileDigest=digest,pqBinding=pin,pqActive=active)
def vote(c,identity,result,expected):
    old=read(c,identity)
    dual.check_vote(c,identity,old)
    if not old:
        if expected is not None:raise ValueError('PQ authorization missing')
        return {}
    if expected!=old[2] or old[3] or not result.get('pqActive') or (result.get('profileSequence'),result.get('profileDigest'),result.get('pqBinding'))!=old[:3]:raise ValueError('PQ authority refused')
    return dict(profileSequence=old[0],profileDigest=old[1],pqBinding=old[2])
