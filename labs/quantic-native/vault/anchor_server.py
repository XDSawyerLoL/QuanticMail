"""Independent, single-vault laboratory checkpoint service. Own host and custody required.
Only an explicitly provisioned ID is accepted. No reset/create via network.
"""
import subprocess
from contextlib import closing
import manifest_store as ms
import registry_lease as rl
import scheduled_registry as sr
import compact_registry as cr
from cryptography.exceptions import InvalidSignature
import urllib.error
import argparse, hashlib, http.server, json, os, pathlib, re, sqlite3, ssl, stat
HEX=re.compile(r'^[0-9a-f]{64}$')
CAP=16384

def valid_hash(v): return isinstance(v,str) and HEX.fullmatch(v) is not None

def provision(db, identity, binding=None, manifest=None):
    if not valid_hash(identity): raise ValueError('invalid identity')
    fd=os.open(db,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600); os.close(fd)
    with sqlite3.connect(db) as c:
        c.execute('PRAGMA synchronous=FULL')
        c.execute('CREATE TABLE checkpoint (id TEXT PRIMARY KEY, count INTEGER NOT NULL, tail TEXT NOT NULL)')
        c.execute('INSERT INTO checkpoint VALUES (?,0,?)',(identity,identity))
        c.execute('CREATE TABLE revocation (id TEXT PRIMARY KEY REFERENCES checkpoint(id))')
        if binding is not None: ms.bind(c,identity,binding,manifest)
    fd=os.open(str(pathlib.Path(db).parent),os.O_RDONLY);os.fsync(fd);os.close(fd)

def connection(db):
    c=sqlite3.connect(pathlib.Path(db).resolve().as_uri()+'?mode=rw',uri=True,timeout=3)
    c.execute('PRAGMA synchronous=FULL');return c

def revoke(db, identity):
    # Administrator acts locally on each independently operated authority.
    # No remote revocation or reactivation endpoint; no delete operation.
    if not valid_hash(identity): raise ValueError('invalid identity')
    c=connection(db)
    try:
        c.execute('BEGIN IMMEDIATE')
        if c.execute('SELECT id FROM checkpoint WHERE id=?',(identity,)).fetchone() is None: raise ValueError('unknown identity')
        c.execute('INSERT OR IGNORE INTO revocation VALUES (?)',(identity,))
        c.commit()
    finally: c.close()

def serve(args):
    info=os.lstat(args.db)
    if not stat.S_ISREG(info.st_mode) or info.st_mode&0o077 or info.st_uid!=os.geteuid(): raise ValueError('private DB required')
    if not valid_hash(args.client_pin): raise ValueError('invalid client pin')
    scheduled=bool(args.scheduled_registry)
    compact=bool(args.compact_registry)
    dual_feed=bool(args.dual_proof_feed)
    if dual_feed and not compact:raise ValueError("dual proof feed requires compact mode")
    if compact and not scheduled:raise ValueError("compact requires scheduled mode")
    if scheduled and not args.registry_url:raise ValueError("scheduled feed required")
    with closing(connection(args.db)) as c, c:
        rows=c.execute('SELECT id,count,tail FROM checkpoint').fetchall()
        c.execute('SELECT id FROM revocation').fetchall() # older databases fail closed
        bound=bool(c.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='signed_manifest'").fetchone())
        if bound!=args.manifest_required: raise ValueError('explicit manifest mode required')
        if args.registry_url and (not bound or not args.registry_pin): raise ValueError("registry requires manifest binding and pin")
        has_registry=bool(c.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='registry_policy'").fetchone())
        if has_registry and not args.registry_url:raise ValueError('fresh registry mode required')
        if args.registry_url:
            if not has_registry:
                c.execute("CREATE TABLE registry_policy (pin TEXT NOT NULL)")
                c.execute("INSERT INTO registry_policy VALUES (?)",(args.registry_pin,))
                c.execute("CREATE TABLE registry_lease (id TEXT PRIMARY KEY, issued INTEGER NOT NULL, expires INTEGER NOT NULL)")
            elif c.execute('SELECT pin FROM registry_policy').fetchall()!=[(args.registry_pin,)]:raise ValueError('registry pin mismatch')
        has_schedule=bool(c.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='schedule_policy'").fetchone())
        if has_schedule and not scheduled:raise ValueError('scheduled registry mode required')
        if scheduled:
            if not all((args.feed_pin,args.feed_ca,args.feed_cert,args.feed_key)):raise ValueError('feed TLS configuration required')
            if not has_schedule:
                c.execute('CREATE TABLE schedule_policy (pin TEXT NOT NULL)')
                c.execute('INSERT INTO schedule_policy VALUES (?)',(args.feed_pin,))
            elif c.execute('SELECT pin FROM schedule_policy').fetchall()!=[(args.feed_pin,)]:raise ValueError('feed pin mismatch')
        has_compact=bool(c.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='compact_policy'").fetchone())
        if has_compact and not compact:raise ValueError('compact registry mode required')
        if compact and not has_compact:c.execute('CREATE TABLE compact_policy (version INTEGER NOT NULL CHECK(version=7))');c.execute('INSERT INTO compact_policy VALUES (7)')
        has_dual=bool(c.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='dual_feed_policy'").fetchone())
        if has_dual and not dual_feed:raise ValueError("dual proof feed mode required")
        if dual_feed and not has_dual:
            c.execute("CREATE TABLE dual_feed_policy (version INTEGER NOT NULL CHECK(version=1))");c.execute("INSERT INTO dual_feed_policy VALUES (1)")
        if bound and c.execute('SELECT id FROM signed_manifest').fetchall()!=[(rows[0][0],)]: raise ValueError('invalid binding')
        if len(rows)!=1 or not valid_hash(rows[0][0]) or not valid_hash(rows[0][2]) or not 0<=rows[0][1]<=CAP: raise ValueError('invalid checkpoint DB')
    worker=None
    if scheduled:
        from dual_proof_feed import DualProofFeed
        feed=(DualProofFeed if dual_feed else cr.CompactFeed if compact else sr.FixedFeed)(args.registry_url,args.feed_pin,args.feed_ca,args.feed_cert,args.feed_key)
        worker=sr.ScheduledRegistry(feed,args.registry_pin,rows[0][0],lambda:connection(args.db),allow_pq=compact,dual_feed=dual_feed)
        worker.start()
    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self,*_): pass
        def setup(self):
            super().setup();self.connection.settimeout(5)
        def answer(self,status,vote=None):
            data=json.dumps(vote,separators=(",",":" )).encode() if status==200 and vote else (b'OK\n' if status==200 else b'REFUSED\n')
            self.send_response(status);self.send_header('Content-Length',str(len(data)));self.send_header('Cache-Control','no-store');self.end_headers();self.wfile.write(data)
        def do_POST(self):
            try:
                if hashlib.sha256(self.connection.getpeercert(binary_form=True)).hexdigest()!=args.client_pin: return self.answer(403)
                fresh_mode=bool(args.registry_url)
                if self.path not in (('/compact-check','/compact-advance')+ (('/compact-proof',) if dual_feed else ()) if compact else ('/scheduled-check','/scheduled-advance') if scheduled else (('/fresh-check','/fresh-advance') if fresh_mode else ('/check','/advance'))):return self.answer(404)
                advance=self.path.endswith('advance')
                n=int(self.headers.get('Content-Length','0'))
                if not 1<=n<=1024 or self.headers.get('Transfer-Encoding'):return self.answer(400)
                p=json.loads(self.rfile.read(n)); keys={'id','count','tail'} | ({'record'} if advance else set())
                if isinstance(p,dict) and 'pqBinding' in p and compact:keys.add('pqBinding')
                if not isinstance(p,dict) or set(p)!=keys or type(p['count']) is not int or not 0<=p['count']<=CAP or not all(valid_hash(p[k]) for k in keys-{'count'}):return self.answer(400)
                lease=rl.pull(args.registry_url,args.registry_pin,p['id']) if fresh_mode and not scheduled else None
                c=connection(args.db)
                try:
                    c.execute('BEGIN IMMEDIATE')
                    if c.execute('SELECT id FROM revocation WHERE id=?',(p['id'],)).fetchone(): c.rollback();return self.answer(403)
                    vote=None
                    if lease:
                        result=rl.apply(c,p['id'],lease)
                        if not result['active']:
                            c.commit();return self.answer(403)
                        vote=dict(sequence=result['sequence'],digest=result['digest'],expires=lease['expires'])
                    if scheduled:vote=worker.vote(c,p['id'],p.get('pqBinding'))
                    if bound and not scheduled and not ms.active(c,p['id']): c.rollback();return self.answer(403)
                    old=c.execute('SELECT count,tail FROM checkpoint WHERE id=?',(p['id'],)).fetchone()
                    if old!=(p['count'],p['tail']): c.rollback();return self.answer(409)
                    if advance:
                        if p['count']>=CAP:c.rollback();return self.answer(409)
                        nxt=hashlib.sha256(bytes.fromhex(p['tail']+p['record'])).hexdigest()
                        c.execute('UPDATE checkpoint SET count=count+1,tail=? WHERE id=?',(nxt,p['id']))
                    if lease:rl.fresh(lease)
                    if scheduled:vote=worker.vote(c,p['id'],p.get('pqBinding'))
                    if self.path=='/compact-proof':vote=worker.public_proof(c,p['id'],p.get('pqBinding'))
                    c.commit()
                finally:c.close()
                return self.answer(200,vote)
            except (ValueError,TypeError,KeyError,sqlite3.Error,OSError,subprocess.SubprocessError,InvalidSignature,urllib.error.URLError):
                try:self.answer(503)
                except OSError:pass
    ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.minimum_version=ssl.TLSVersion.TLSv1_3;ctx.load_cert_chain(args.cert,args.key);ctx.load_verify_locations(args.ca);ctx.verify_mode=ssl.CERT_REQUIRED
    with http.server.HTTPServer((args.host,args.port),Handler) as srv:
        srv.socket=ctx.wrap_socket(srv.socket,server_side=True)
        print(json.dumps({'port':srv.server_address[1]}),flush=True);srv.serve_forever()

if __name__=='__main__':
    p=argparse.ArgumentParser();s=p.add_subparsers(dest='mode',required=True);i=s.add_parser('init');i.add_argument('db');i.add_argument('id');r=s.add_parser('revoke');r.add_argument('db');r.add_argument('id');a=s.add_parser('serve');a.add_argument('db');a.add_argument('--host',default='127.0.0.1');a.add_argument('--port',type=int,default=9443)
    a.add_argument('--manifest-required',action='store_true')
    a.add_argument('--registry-url');a.add_argument('--registry-pin')
    a.add_argument('--scheduled-registry',action='store_true')
    a.add_argument('--compact-registry',action='store_true')
    a.add_argument('--dual-proof-feed',action='store_true')
    for name in ['feed-pin','feed-ca','feed-cert','feed-key']:a.add_argument('--'+name)
    m=s.add_parser('init-manifest');m.add_argument('db');m.add_argument('id');m.add_argument('binding');m.add_argument('manifest')
    u=s.add_parser('publish-manifest');u.add_argument('db');u.add_argument('id');u.add_argument('manifest')
    for name in ['cert','key','ca','client-pin']:a.add_argument('--'+name,required=True)
    args=p.parse_args()
    if args.mode=='init':provision(args.db,args.id)
    elif args.mode=='init-manifest':provision(args.db,args.id,ms.bounded(args.binding),ms.bounded(args.manifest))
    elif args.mode=='publish-manifest':
        c=connection(args.db)
        try:
            c.execute('BEGIN IMMEDIATE');ms.publish(c,args.id,ms.bounded(args.manifest));c.commit()
        finally:c.close()
    elif args.mode=='revoke':revoke(args.db,args.id)
    else:serve(args)
