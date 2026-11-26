"""Synthetic local registry: distinct feeds, signed published lease."""
import copy,time,threading,http.server,json,base64,pathlib,subprocess,sys,unittest
from test_manifest_scattering import ManifestQuorum,Ed25519PrivateKey,BRIDGE,b64,serialization,stamp
HERE=pathlib.Path(__file__).resolve().parent
class FreshRegistry(ManifestQuorum):
    provision_mode='--provision-software-fresh-manifest-quorum-lab'
    broker_mode='--broker-software-fresh-manifest-quorum-lab'
    def setUp(self):
        self.registry_key=Ed25519PrivateKey.generate();self.registry_pin=self.registry_key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw).hex();self.feeds=[b'{}']*4;self.servers=[]
        for i in range(4):
            def factory(i):
                owner=self
                class Handler(http.server.BaseHTTPRequestHandler):
                    def log_message(self,*a):pass
                    def do_GET(self):
                        data=owner.feeds[i];self.send_response(200);self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)
                return Handler
            srv=http.server.ThreadingHTTPServer(('127.0.0.1',0),factory(i));self.servers.append(srv);threading.Thread(target=srv.serve_forever,daemon=True).start();self.addCleanup(srv.server_close);self.addCleanup(srv.shutdown)
        super().setUp();self.publish_lease(self.initial)
    def publish_lease(self,m,indices=range(4),issued=None,expires=None,key=None):
        now=time.time_ns()//1000000 if issued is None else issued
        p=json.dumps(dict(id=self.id,manifest=m,issued=now,expires=now+30000 if expires is None else expires),separators=(',',':')).encode()
        data=json.dumps(dict(payload=base64.b64encode(p).decode(),signature=base64.b64encode((key or self.registry_key).sign(b'quantic-registry-lease-lab/v1\0'+p)).decode())).encode()
        for i in indices:self.feeds[i]=data
    def start(self,i):
        n=self.nodes[i];d=n['d'];n['proc']=subprocess.Popen([sys.executable,str(HERE/'anchor_server.py'),'serve',str(n['db']),'--port','0','--cert',str(d/'server.pem'),'--key',str(d/'server.key'),'--ca',str(d/'ca.pem'),'--client-pin',n['pins']['client'],'--manifest-required','--registry-url',f'http://127.0.0.1:{self.servers[i].server_port}/lease','--registry-pin',self.registry_pin],stdout=subprocess.PIPE,stderr=subprocess.PIPE);n['port']=json.loads(n['proc'].stdout.readline())['port'];n['direct_port']=n['port']
        n['bridge']=subprocess.Popen(['node',str(BRIDGE),str(n['port']),'--synthetic-loopback-only'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True);n['port']=json.loads(n['bridge'].stdout.readline())['port']
    def test_split_then_sync_then_revoke(self):
        changed=copy.deepcopy(self.payload);changed['sequence']=2;changed['issuedAt']=stamp();changed['devices'][1]['label']='Native updated';m=self.signed(changed)
        self.publish_lease(m,(0,1));self.reject_start()
        self.publish_lease(m);a=self.enter();self.decrypt(a);self.assertEqual(self.counts(),[1]*4)
        rev=copy.deepcopy(changed);rev['sequence']=3;rev['devices']=rev['devices'][:1];rev['revocations']=[dict(deviceId=self.device,revokedAt=stamp(),reason='compromised')];self.publish_lease(self.signed(rev),(0,1,2))
        pub=a.q('public');pkt=a.q('seal',recipient=pub['encryption'],message=b64(b'never released'))['packet'];a.request('open',packet=pkt);a.child.prompt(b'[taper OUI] : ',b'OUI');self.assertNotEqual(a.child.p.wait(timeout=12),0);self.assertEqual(a.child.p.stdout.read(),b'');self.reject_start()
    def test_expired_and_wrong_signer(self):
        now=time.time_ns()//1000000;self.publish_lease(self.initial,issued=now-3000,expires=now-1000);self.reject_start()
        self.publish_lease(self.initial,key=Ed25519PrivateKey.generate());self.reject_start()
        self.publish_lease(self.initial);a=self.enter();self.decrypt(a);self.close(a)
        self.assertEqual(self.counts(),[1]*4)
    def test_registry_outage_live(self):
        a=self.enter();self.decrypt(a)
        for i in (0,1,2):self.servers[i].shutdown();self.servers[i].server_close()
        pub=a.q('public');pkt=a.q('seal',recipient=pub['encryption'],message=b64(b'not released'))['packet'];a.request('open',packet=pkt);a.child.prompt(b'[taper OUI] : ',b'OUI');self.assertNotEqual(a.child.p.wait(timeout=12),0);self.assertEqual(a.child.p.stdout.read(),b'');self.assertEqual(self.counts(),[1,1,1,2])
