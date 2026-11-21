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
    def __init__(self,feed,pin,identity,connection,allow_pq=False):
        self.feed=feed;self.pin=pin;self.identity=identity;self.connection=connection;self.allow_pq=allow_pq
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
            p=rl.decode(self.feed.fetch(),self.pin,self.identity)
            c=self.connection()
            try:
                c.execute('BEGIN IMMEDIATE')
                old=c.execute('SELECT issued,expires FROM registry_lease WHERE id=?',(self.identity,)).fetchone()
                current=c.execute('SELECT manifest FROM signed_manifest WHERE id=?',(self.identity,)).fetchone()
                if old and p['issued']==old[0] and (not current or json.loads(current[0])!=p['manifest']):raise ValueError('same issued lease conflict')
                result=rl.apply(c,self.identity,p,allow_pq=self.allow_pq)
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
