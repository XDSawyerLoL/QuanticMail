"""Fixed-cadence registry reader. Loopback TLS laboratory, no user's data.
Only the worker initiates requests; votes never trigger a network fetch.
"""
import hashlib, http.client, json, re, ssl, struct, threading, time, urllib.parse
import registry_lease as rl
import pq_profile as pq
PERIOD=1.0
MAX_AGE=4.0
REQUEST_SIZE=256
RESPONSE_SIZE=16384

def pack_lease(raw):
    if not isinstance(raw,bytes) or not 0<len(raw)<=RESPONSE_SIZE-4:raise ValueError('lease size')
    return struct.pack('!I',len(raw))+raw+bytes(RESPONSE_SIZE-4-len(raw))

def unpack_lease(raw):
    if len(raw)!=RESPONSE_SIZE:raise ValueError('fixed response required')
    n=struct.unpack('!I',raw[:4])[0]
    if not 0<n<=RESPONSE_SIZE-4 or any(raw[4+n:]):raise ValueError('bad padding')
    return raw[4:4+n]

class FixedFeed:
    def __init__(self,url,server_pin,ca,cert,key):
        u=urllib.parse.urlsplit(url)
        if u.scheme!='https' or u.hostname!='localhost' or not u.port or u.path!='/lease' or u.username or u.password or u.query or u.fragment:raise ValueError('explicit loopback TLS feed required')
        if not re.fullmatch('[0-9a-f]{64}',server_pin):raise ValueError('bad feed pin')
        self.port=u.port;self.pin=server_pin
        self.ctx=ssl.create_default_context(cafile=ca);self.ctx.minimum_version=ssl.TLSVersion.TLSv1_3;self.ctx.load_cert_chain(cert,key)
    def fetch(self):
        c=http.client.HTTPSConnection('localhost',self.port,context=self.ctx,timeout=.8)
        try:
            c.connect()
            if hashlib.sha256(c.sock.getpeercert(binary_form=True)).hexdigest()!=self.pin:raise ValueError('feed TLS pin mismatch')
            c.request('POST','/lease',body=bytes(REQUEST_SIZE),headers={'Content-Type':'application/octet-stream','Connection':'close'})
            r=c.getresponse()
            if r.status!=200 or r.getheader('Content-Length')!=str(RESPONSE_SIZE) or r.getheader('Transfer-Encoding'):raise ValueError('fixed feed response required')
            return unpack_lease(r.read(RESPONSE_SIZE+1))
        finally:c.close()

class ScheduledRegistry:
    def __init__(self,feed,pin,identity,connection,allow_pq=False,dual_feed=False,contact_feed=False):
        self.feed=feed;self.pin=pin;self.identity=identity;self.connection=connection;self.allow_pq=allow_pq;self.dual_feed=dual_feed;self.contact_feed=contact_feed
        self.lock=threading.Lock();self.snapshot=None;self.stop=threading.Event()
        self.thread=threading.Thread(target=self.run,daemon=True)
    def start(self):self.thread.start()
    def close(self):self.stop.set();self.thread.join(timeout=5)
    def run(self):
        tick=time.monotonic()
        while not self.stop.is_set():
            self.refresh()
            tick+=PERIOD
            # Skip elapsed slots, never catch up with an activity-dependent burst.
            now=time.monotonic()
            if tick<=now:tick+=((now-tick)//PERIOD+1)*PERIOD
            self.stop.wait(max(0,tick-time.monotonic()))
    def refresh(self):
        started=time.monotonic()
        try:
            raw=self.feed.fetch()
            signature=None;contact=None
            if self.contact_feed:raw,signature,contact=raw
            elif self.dual_feed:raw,signature=raw
            p=rl.decode(raw,self.pin,self.identity)
            c=self.connection()
            try:
                c.execute('BEGIN IMMEDIATE')
                old=c.execute('SELECT issued,expires FROM registry_lease WHERE id=?',(self.identity,)).fetchone()
                current=c.execute('SELECT manifest FROM signed_manifest WHERE id=?',(self.identity,)).fetchone()
                if old and p['issued']==old[0] and (not current or json.loads(current[0])!=p['manifest']):raise ValueError('same issued lease conflict')
                if self.dual_feed:
                    import dual_proof_feed as dpf
                    dpf.stage(c,self.identity,p,signature)
                result=rl.apply(c,self.identity,p,allow_pq=self.allow_pq)
                if self.contact_feed:
                    import contact_permission as cp
                    if contact is not None:
                        cp.stage(c,self.identity,contact)
                        result['contactPayload']=cp.digest(cp.canonical(contact['payload']))
                        result['contactId']=contact['payload']['contactId']
                rl.fresh(p)
                if time.monotonic()-started>=MAX_AGE:raise ValueError('slow refresh')
                c.commit()
            finally:c.close()
            with self.lock:self.snapshot=(p,result,started)
        except Exception:
            # Any failed poll invalidates cached authority, not a retry-on-demand.
            with self.lock:self.snapshot=None
    def vote(self,c,identity,expected=None):
        with self.lock:s=self.snapshot
        if s is None or identity!=self.identity:raise ValueError('no scheduled authority')
        p,result,started=s
        age=time.monotonic()-started
        if not 0<=age<MAX_AGE:raise ValueError('stale refresh')
        rl.fresh(p)
        # The checkpoint transaction sees the durable state the worker validated.
        row=c.execute('SELECT manifest,denied FROM signed_manifest WHERE id=?',(identity,)).fetchone()
        old=c.execute('SELECT issued,expires FROM registry_lease WHERE id=?',(identity,)).fetchone()
        if not row or row[1] or not result['active'] or json.loads(row[0])!=p['manifest'] or old!=(p['issued'],p['expires']):raise ValueError('revoked or divergent durable state')
        expiry=min(p['expires'],time.time_ns()//1000000+int((MAX_AGE-age)*1000))
        return dict(sequence=result['sequence'],digest=result['digest'],expires=expiry,**pq.vote(c,identity,result,expected))

    def public_proof(self,c,identity,expected):
        # Explicit startup read only; no refresh or network request triggered.
        if not self.dual_feed or not expected:raise ValueError('dual proof mode required')
        vote=self.vote(c,identity,expected)
        with self.lock:s=self.snapshot
        if s is None:raise ValueError('no current proof')
        p,result,_=s
        import base64
        import pq_dual_authority as dual
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives import serialization
        grant=p.get('pqProfile')
        r=dual.root(c,identity);st=dual.staged(c,identity)
        if not grant or not r or not st or not grant['payload']['active']:raise ValueError('no active proof')
        if grant['payload']['sequence']!=vote['profileSequence'] or st[:2]!=(vote['profileSequence'],dual.sha(pq.canonical(grant['payload']))) or dual.combined_digest(r[0],st[1])!=vote['profileDigest']:raise ValueError('proof state diverged')
        point=p['manifest']['payload']['identitySigningPublicKey']
        def dec(s):return base64.urlsafe_b64decode(s+'='*(-len(s)%4))
        key=ec.EllipticCurvePublicNumbers(int.from_bytes(dec(point['x']),'big'),int.from_bytes(dec(point['y']),'big'),ec.SECP256R1()).public_key()
        def enc(b):return base64.b64encode(b).decode()
        wire=dict(sequence=st[0],classicalRoot=enc(key.public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)),pqRoot=enc(r[1]),classicalSignature=grant['signature'],pqSignature=enc(st[2]))
        self.vote(c,identity,expected)
        return wire

    def contact_vote(self,c,identity,expected,contact,commitment):
        import contact_permission as cp
        # All contact permissions in this mode must be present in the current
        # scheduled snapshot, not merely present in a previously populated DB.
        vote=self.vote(c,identity,expected)
        if self.contact_feed:
            with self.lock:s=self.snapshot
            if s is None or s[1].get('contactId')!=contact:raise ValueError('no current contact snapshot')
            d=c.execute('SELECT payload_digest FROM contact_permission WHERE id=? AND contact=?',(identity,contact)).fetchone()
            if not d or d[0]!=s[1].get('contactPayload'):raise ValueError('contact snapshot diverged')
        vote['contactCommitment']=cp.require(c,identity,contact,commitment)
        return vote
