"""Explicit fixed contact-permission feed (one contact per frame, lab).
No private keys or signing on the feed or witness.
"""
import struct,json
import dual_proof_feed as dpf
RESPONSE_SIZE=12288
MAGIC=b'QCP1'
CORE_SIZE=5365
def pack(raw,signature=None,contact=None):
    core=dpf.pack(raw,signature)[:CORE_SIZE]
    grant=b'' if contact is None else json.dumps(contact,separators=(',',':'),ensure_ascii=True).encode()
    if len(grant)>RESPONSE_SIZE-8-CORE_SIZE:raise ValueError('contact frame overflow')
    data=MAGIC+struct.pack('!I',len(grant))+core+grant
    return data+bytes(RESPONSE_SIZE-len(data))
def unpack(frame):
    if not isinstance(frame,bytes) or len(frame)!=RESPONSE_SIZE or frame[:4]!=MAGIC:raise ValueError('contact frame required')
    n=struct.unpack('!I',frame[4:8])[0]
    start=8+CORE_SIZE
    if n>RESPONSE_SIZE-start or any(frame[start+n:]):raise ValueError('invalid contact frame padding')
    raw,sig=dpf.unpack(frame[8:start]+bytes(dpf.RESPONSE_SIZE-CORE_SIZE))
    grant=json.loads(frame[start:start+n]) if n else None
    if n and not isinstance(grant,dict):raise ValueError('contact grant required')
    return raw,sig,grant
class ContactFeed(dpf.DualProofFeed):
    response_size=RESPONSE_SIZE
    unpack_frame=staticmethod(unpack)
