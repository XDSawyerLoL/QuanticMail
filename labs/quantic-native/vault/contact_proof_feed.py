"""QCP2: fixed two-slot contact proof feed, laboratory only."""
import struct,json,base64
import dual_proof_feed as dpf
RESPONSE_SIZE=14336
MAGIC=b'QCP2'
CORE_SIZE=5365
MAX_CONTACTS=2
SLOT=4480
def encode_grant(g):
    if not isinstance(g,dict) or set(g)!={'payload','classicalSignature','pqSignature'}:raise ValueError('invalid grant')
    raw=json.dumps(g['payload'],separators=(',',':'),ensure_ascii=True).encode()
    a=base64.b64decode(g['classicalSignature'],validate=True);b=base64.b64decode(g['pqSignature'],validate=True)
    if len(a)!=64 or len(b)!=3309 or not 0<len(raw)<=SLOT-4-64-3309:raise ValueError('invalid grant size')
    data=struct.pack('!I',len(raw))+raw+a+b
    return data+bytes(SLOT-len(data))
def decode_grant(slot):
    n=struct.unpack('!I',slot[:4])[0]
    if n==0:
        if any(slot):raise ValueError('invalid empty slot')
        return None
    end=4+n+64+3309
    if end>SLOT or any(slot[end:]):raise ValueError('invalid slot padding')
    p=json.loads(slot[4:4+n])
    if not isinstance(p,dict):raise ValueError('invalid grant payload')
    return dict(payload=p,classicalSignature=base64.b64encode(slot[4+n:4+n+64]).decode(),pqSignature=base64.b64encode(slot[4+n+64:end]).decode())
def pack(raw,signature=None,contacts=None):
    core=dpf.pack(raw,signature)[:CORE_SIZE]
    contacts=[] if contacts is None else contacts
    if not isinstance(contacts,list) or len(contacts)>MAX_CONTACTS:raise ValueError('contact capacity')
    ids=[g['payload']['contactId'] for g in contacts]
    if len(ids)!=len(set(ids)):raise ValueError('duplicate contact')
    slots=b''.join(encode_grant(g) for g in contacts)+bytes(SLOT*(MAX_CONTACTS-len(contacts)))
    data=MAGIC+core+slots
    if len(data)>RESPONSE_SIZE:raise ValueError('frame overflow')
    return data+bytes(RESPONSE_SIZE-len(data))
def unpack(frame):
    if not isinstance(frame,bytes) or len(frame)!=RESPONSE_SIZE or frame[:4]!=MAGIC:raise ValueError('QCP2 frame required')
    start=4+CORE_SIZE
    if any(frame[start+SLOT*MAX_CONTACTS:]):raise ValueError('invalid frame padding')
    raw,sig=dpf.unpack(frame[4:start]+bytes(dpf.RESPONSE_SIZE-CORE_SIZE))
    grants=[];empty=False
    for i in range(MAX_CONTACTS):
        g=decode_grant(frame[start+i*SLOT:start+(i+1)*SLOT])
        if g is None:empty=True
        else:
            if empty:raise ValueError('noncanonical slots')
            grants.append(g)
    ids=[g['payload']['contactId'] for g in grants]
    if len(ids)!=len(set(ids)):raise ValueError('duplicate contact')
    return raw,sig,grants
class ContactFeed(dpf.DualProofFeed):
    response_size=RESPONSE_SIZE
    unpack_frame=staticmethod(unpack)
