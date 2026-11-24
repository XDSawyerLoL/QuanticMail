"""Four Scattering bridges and four pinned mTLS scheduled registry feeds."""
from contextlib import closing
import hashlib,http.server,json,pathlib,ssl,subprocess,sys,tempfile,threading,time,unittest,sqlite3
from test_fresh_registry import FreshRegistry,ManifestQuorum,BRIDGE,Ed25519PrivateKey,serialization,b64
from test_anchor import certs,LocalProcess,PASSWORD
from scheduled_registry import pack_lease,REQUEST_SIZE,RESPONSE_SIZE
HERE=pathlib.Path(__file__).resolve().parent
class Scheduled(FreshRegistry):
    provision_mode='--provision-software-scheduled-manifest-quorum-lab'
    broker_mode='--broker-software-scheduled-manifest-quorum-lab'
    def setUp(self):
        self.registry_key=Ed25519PrivateKey.generate();self.registry_pin=self.registry_key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw).hex();self.feeds=[b'{}']*4;self.servers=[];self.logs=[[] for _ in range(4)];self.feed_dir=tempfile.TemporaryDirectory();self.addCleanup(self.feed_dir.cleanup);self.feed_certs=[]
        for i in range(4):
            d=pathlib.Path(self.feed_dir.name)/str(i);d.mkdir(mode=0o700);pins=certs(d);self.feed_certs.append((d,pins))
            def factory(i,pins):
                owner=self
                class Handler(http.server.BaseHTTPRequestHandler):
                    def log_message(self,*a):pass
                    def do_POST(self):
                        if self.path!='/lease' or hashlib.sha256(self.connection.getpeercert(binary_form=True)).hexdigest()!=pins['client'] or self.headers.get('Content-Length')!=str(REQUEST_SIZE) or self.rfile.read(REQUEST_SIZE)!=bytes(REQUEST_SIZE):self.send_error(403);return
                        data=pack_lease(owner.feeds[i]);owner.logs[i].append((time.monotonic(),REQUEST_SIZE,len(data)));self.send_response(200);self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)
                return Handler
            srv=http.server.ThreadingHTTPServer(('127.0.0.1',0),factory(i,pins));ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.minimum_version=ssl.TLSVersion.TLSv1_3;ctx.load_cert_chain(d/'server.pem',d/'server.key');ctx.load_verify_locations(d/'ca.pem');ctx.verify_mode=ssl.CERT_REQUIRED;srv.socket=ctx.wrap_socket(srv.socket,server_side=True);self.servers.append(srv);threading.Thread(target=srv.serve_forever,daemon=True).start();self.addCleanup(srv.server_close);self.addCleanup(srv.shutdown)
        ManifestQuorum.setUp(self);self.publish_lease(self.initial);self.wait_lease(self.initial)
    def start(self,i):
        n=self.nodes[i];d=n['d'];f,pins=self.feed_certs[i];n['proc']=subprocess.Popen([sys.executable,str(HERE/'anchor_server.py'),'serve',str(n['db']),'--port','0','--cert',str(d/'server.pem'),'--key',str(d/'server.key'),'--ca',str(d/'ca.pem'),'--client-pin',n['pins']['client'],'--manifest-required','--registry-url',f'https://localhost:{self.servers[i].server_port}/lease','--registry-pin',self.registry_pin,'--scheduled-registry','--feed-pin',pins['server'],'--feed-ca',str(f/'ca.pem'),'--feed-cert',str(f/'client.pem'),'--feed-key',str(f/'client.key')],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        line=n['proc'].stdout.readline();assert line,n['proc'].stderr.read();n['port']=json.loads(line)['port'];n['direct_port']=n['port'];n['bridge']=subprocess.Popen(['node',str(BRIDGE),str(n['port']),'--synthetic-loopback-only'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True);n['port']=json.loads(n['bridge'].stdout.readline())['port']
    def wait_lease(self,m,ids=range(4)):
        end=time.monotonic()+9
        while time.monotonic()<end:
            good=True
            for i in ids:
                with closing(sqlite3.connect(self.nodes[i]['db'])) as c:
                    row=c.execute('SELECT manifest FROM signed_manifest').fetchone();lease=c.execute('SELECT issued FROM registry_lease').fetchone()
                    good &= bool(row and lease and json.loads(row[0])==m)
            if good:time.sleep(.25);return
            time.sleep(.1)
        self.fail('background sync did not reach required witnesses')
    def report(self):
        for i,logs in enumerate(self.logs):
            gaps=[b[0]-a[0] for a,b in zip(logs,logs[1:])];self.assertTrue(all(x[1:]==(REQUEST_SIZE,RESPONSE_SIZE) for x in logs));print('registry_feed',i,'requests',len(logs),'gap_min_s',round(min(gaps,default=0),3),'gap_max_s',round(max(gaps,default=0),3),'fixed_body',REQUEST_SIZE,RESPONSE_SIZE,flush=True)
    def test_idle_active_revoke(self):
        before=list(map(len,self.logs));time.sleep(3.1);idle=[len(l)-n for l,n in zip(self.logs,before)];self.assertTrue(all(x>=2 for x in idle),idle);print('idle_poll_counts',idle,flush=True)
        a=self.enter();self.decrypt(a);self.assertEqual(self.counts(),[1]*4)
        legacy=LocalProcess(['--broker-software-fresh-manifest-quorum-lab',*self.args[1:]]);self.addCleanup(legacy.close);legacy.prompt(b' : ',PASSWORD,True);self.assertNotEqual(legacy.p.wait(timeout=8),0);self.assertEqual(legacy.p.stdout.read(),b'')
        rev=self.revoked();self.publish_lease(rev,(0,1,2));self.wait_lease(rev,(0,1,2))
        pub=a.q('public');pkt=a.q('seal',recipient=pub['encryption'],message=b64(b'not released'))['packet'];a.request('open',packet=pkt);a.child.prompt(b'[taper OUI] : ',b'OUI');self.assertNotEqual(a.child.p.wait(timeout=12),0);self.assertEqual(a.child.p.stdout.read(),b'');self.report()
    def test_failure_invalidates_cache(self):
        a=self.enter();self.decrypt(a)
        self.publish_lease(self.initial,(0,1,2),key=Ed25519PrivateKey.generate());time.sleep(3.1)
        pub=a.q('public');pkt=a.q('seal',recipient=pub['encryption'],message=b64(b'not released'))['packet'];a.request('open',packet=pkt);a.child.prompt(b'[taper OUI] : ',b'OUI');self.assertNotEqual(a.child.p.wait(timeout=12),0);self.assertEqual(a.child.p.stdout.read(),b'');self.report()
if __name__=='__main__':unittest.main()
