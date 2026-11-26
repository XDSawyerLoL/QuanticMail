"""RC7 public signed lease compression, bounded fixed frames over pinned TLS.
Never compress secret material or attacker-chosen data together with secrets.
"""
import hashlib,http.client,struct,zlib
from scheduled_registry import FixedFeed,REQUEST_SIZE
RESPONSE_SIZE=2048
MAX_RAW=16380
MAGIC=b'QRC7'
def pack_lease(raw):
    if not isinstance(raw,bytes) or not 0<len(raw)<=MAX_RAW:raise ValueError('lease size')
    data=zlib.compress(raw,9)
    if len(data)>RESPONSE_SIZE-8:raise ValueError('compressed lease exceeds fixed frame')
    return MAGIC+struct.pack('!I',len(data))+data+bytes(RESPONSE_SIZE-8-len(data))
def unpack_lease(frame):
    if len(frame)!=RESPONSE_SIZE or frame[:4]!=MAGIC:raise ValueError('compact frame required')
    n=struct.unpack('!I',frame[4:8])[0]
    if not 0<n<=RESPONSE_SIZE-8 or any(frame[8+n:]):raise ValueError('bad compact padding')
    d=zlib.decompressobj()
    try: raw=d.decompress(frame[8:8+n],MAX_RAW+1)
    except zlib.error as e:raise ValueError('invalid compressed lease') from e
    if not 0<len(raw)<=MAX_RAW or not d.eof or d.unconsumed_tail or d.unused_data:raise ValueError('invalid compressed lease bounds')
    return raw
class CompactFeed(FixedFeed):
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
            # No implicit reconnect (HTTPConnection.request otherwise can reconnect).
            if c.sock is None or hashlib.sha256(c.sock.getpeercert(binary_form=True)).hexdigest()!=self.pin:raise ValueError('feed TLS pin mismatch')
            c.request('POST','/lease',body=bytes(REQUEST_SIZE),headers={'Content-Type':'application/octet-stream','Connection':'keep-alive'})
            r=c.getresponse()
            if r.status!=200 or r.getheader('Content-Length')!=str(RESPONSE_SIZE) or r.getheader('Transfer-Encoding') or r.will_close:raise ValueError('persistent compact feed required')
            return unpack_lease(r.read(RESPONSE_SIZE+1))
        except Exception:
            self.close();raise
