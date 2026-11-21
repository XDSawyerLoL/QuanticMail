"""Fixed-size public detached proof transport; synthetic laboratory only."""
import struct,json,hashlib,http.client
from compact_registry import pack_lease,unpack_lease
from scheduled_registry import FixedFeed,REQUEST_SIZE
import pq_dual_authority as dual
RESPONSE_SIZE=8192
MAGIC=b'QDP1'
SIGNATURE_SIZE=3309

def pack(raw,signature=None):
    if signature is not None and (not isinstance(signature,bytes) or len(signature)!=SIGNATURE_SIZE):raise ValueError('invalid detached proof')
    proof=signature or b''
    data=MAGIC+struct.pack('!I',len(proof))+pack_lease(raw)+proof
    return data+bytes(RESPONSE_SIZE-len(data))

def unpack(frame):
    if not isinstance(frame,bytes) or len(frame)!=RESPONSE_SIZE or frame[:4]!=MAGIC:raise ValueError('dual frame required')
    n=struct.unpack('!I',frame[4:8])[0]
    if n not in (0,SIGNATURE_SIZE) or any(frame[2056+n:]):raise ValueError('invalid dual frame padding')
    return unpack_lease(frame[8:2056]),frame[2056:2056+n] or None

def stage(c,identity,lease,signature):
    grant=lease.get('pqProfile')
    pinned=dual.root(c,identity)
    if not pinned:
        if grant is not None or signature is not None:raise ValueError('independent root pin required')
        return
    if grant is None or signature is None:raise ValueError('dual proof missing')
    row=c.execute('SELECT binding,manifest FROM signed_manifest WHERE id=?',(identity,)).fetchone()
    if not row:raise ValueError('unbound identity')
    dual.stage(c,identity,json.loads(row[0]),json.loads(row[1]),grant,signature)

class DualProofFeed(FixedFeed):
    def __init__(self,*args):
        super().__init__(*args);self.conn=None
    def close(self):
        if self.conn:self.conn.close();self.conn=None
    def fetch(self):
        try:
            if self.conn is None:
                self.conn=http.client.HTTPSConnection('localhost',self.port,context=self.ctx,timeout=2.5)
                self.conn.connect()
            c=self.conn
            if c.sock is None or hashlib.sha256(c.sock.getpeercert(binary_form=True)).hexdigest()!=self.pin:raise ValueError('feed TLS pin mismatch')
            c.request('POST','/lease',body=bytes(REQUEST_SIZE),headers={'Content-Type':'application/octet-stream','Connection':'keep-alive'})
            r=c.getresponse()
            if r.status!=200 or r.getheader('Content-Length')!=str(RESPONSE_SIZE) or r.getheader('Transfer-Encoding') or r.will_close:raise ValueError('dual feed required')
            return unpack(r.read(RESPONSE_SIZE+1))
        except Exception:
            self.close();raise
