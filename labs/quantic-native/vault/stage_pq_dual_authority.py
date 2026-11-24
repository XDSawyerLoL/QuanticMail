"""Trusted local operator: install independent root pin or stage a dual-signed grant.
No network or root private key. Explicit laboratory command, no overwrite/reset.
"""
import argparse,json,os,stat,pathlib
from contextlib import closing
import anchor_server as server
import pq_dual_authority as dual

def read(path,limit):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as f:
        st=os.fstat(f.fileno())
        if not stat.S_ISREG(st.st_mode) or st.st_size>limit:raise ValueError('bounded regular file required')
        data=f.read(limit+1)
        if len(data)>limit:raise ValueError('file too large')
        return data

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--synthetic-lab-only',action='store_true',required=True);p.add_argument('db');p.add_argument('identity');sp=p.add_subparsers(dest='action',required=True)
    i=sp.add_parser('pin-root');i.add_argument('public_der');i.add_argument('independent_pin')
    s=sp.add_parser('stage-proof');s.add_argument('signed_grant_json');s.add_argument('mldsa_signature')
    a=p.parse_args();info=os.lstat(a.db)
    if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or info.st_mode&0o077:raise ValueError('private DB required')
    with closing(server.connection(a.db)) as c,c:
        c.execute('BEGIN IMMEDIATE')
        if a.action=='pin-root':dual.install(c,a.identity,read(a.public_der,1974),a.independent_pin)
        else:
            row=c.execute('SELECT binding,manifest FROM signed_manifest WHERE id=?',(a.identity,)).fetchone()
            if not row:raise ValueError('unbound identity')
            dual.stage(c,a.identity,json.loads(row[0]),json.loads(row[1]),json.loads(read(a.signed_grant_json,8192)),read(a.mldsa_signature,3309))
    print('Lab authority state committed. No live grant publication or key migration.')
if __name__=='__main__':main()
