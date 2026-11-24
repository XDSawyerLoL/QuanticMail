import tempfile
from test_quorum import certs,Ed25519PrivateKey
from test_quorum_scattering import BRIDGE
import copy,hashlib,json,pathlib,subprocess,sys,unittest,datetime,base64
from test_quorum_scattering import IntegratedQuorum
from test_anchor import BINARY,ec,hashes,serialization,unb64,b64,LocalProcess,PASSWORD
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
HERE=pathlib.Path(__file__).resolve().parent
H=lambda x:hashlib.sha256(x).hexdigest()
def jwk(pub):
    raw=pub.public_bytes(serialization.Encoding.X962,serialization.PublicFormat.UncompressedPoint) if not isinstance(pub,bytes) else pub
    return dict(kty='EC',crv='P-256',x=b64(raw[1:33]),y=b64(raw[33:65]))
def digest(k):return H(('P-256:'+k['x']+':'+k['y']).encode())
def stamp():return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='milliseconds').replace('+00:00','Z')
class ManifestQuorum(IntegratedQuorum):
    provision_mode="--provision-software-manifest-quorum-lab"
    broker_mode="--broker-software-manifest-quorum-lab"
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.d=pathlib.Path(self.tmp.name); self.local=self.d/'local';self.local.mkdir(mode=0o700)
        self.vault=self.local/'vault';self.journal=self.local/'journal';self.conf=self.local/'quorum.json';self.appkey=Ed25519PrivateKey.generate();self.app=b64(self.appkey.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw));self.nodes=[]
        self.addCleanup(self.stop_all)
        for i in range(4):
            d=self.d/str(i);d.mkdir(mode=0o700);self.nodes.append(dict(d=d,pins=certs(d),db=d/'check.db',proc=None))
        pin=hashlib.sha256(b'quantic-anchor-quorum-lab/v1\0' + b'3-of-4\0'+''.join(sorted(n['pins']['server'] for n in self.nodes)).encode()).hexdigest();self.pin=pin
        create=LocalProcess([self.provision_mode,self.vault,pin]);self.addCleanup(create.close);create.prompt(b' : ',PASSWORD,True);create.prompt(b' : ',PASSWORD,True);p=create.reply();self.assertEqual(create.p.wait(timeout=5),0)
        self.args=[self.broker_mode,self.vault,p['signingPin'],p['encryptionPin'],self.app,self.journal,self.conf];subprocess.run([str(BINARY),'--init-replay-lab',str(self.journal),p['signingPin'],p['encryptionPin'],self.app],check=True);self.old=self.journal.read_bytes();self.id=hashlib.sha256(self.old).hexdigest()
        self.prepare_manifest(p)
        for i,n in enumerate(self.nodes):
            subprocess.run([sys.executable,str(HERE/'anchor_server.py'),'init-manifest',str(n['db']),self.id,str(self.bindfile),str(self.mfile)],check=True);n['old']=n['db'].read_bytes();self.start(i)
        self.config()
    def start(self,i):
        n=self.nodes[i];d=n['d'];n['proc']=subprocess.Popen([sys.executable,str(HERE/'anchor_server.py'),'serve',str(n['db']),'--port','0','--cert',str(d/'server.pem'),'--key',str(d/'server.key'),'--ca',str(d/'ca.pem'),'--client-pin',n['pins']['client'],'--manifest-required'],stdout=subprocess.PIPE,stderr=subprocess.PIPE);n['port']=json.loads(n['proc'].stdout.readline())['port']
        n=self.nodes[i];n['direct_port']=n['port']
        n['bridge']=subprocess.Popen(['node',str(BRIDGE),str(n['port']),'--synthetic-loopback-only'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        n['port']=json.loads(n['bridge'].stdout.readline())['port']
    def prepare_manifest(self,p):
        self.root=ec.generate_private_key(ec.SECP256R1());rootj=jwk(self.root.public_key());rootenc=jwk(ec.generate_private_key(ec.SECP256R1()).public_key());enc=jwk(unb64(p['encryption']));sig=jwk(unb64(p['signing']));self.device='d-'+digest(enc)[:32];fp=digest(rootj)[:32];address='lab~'+fp+'@quantic';date=stamp()
        self.payload=dict(version=1,sequence=1,canonicalAddress=address,handle='lab',fingerprint=fp,identityPublicKey=rootenc,identitySigningPublicKey=rootj,devices=[dict(deviceId='d-'+digest(rootenc)[:32],label='Root lab',publicKey=rootenc,deviceSigningPublicKey=rootj,kind='root',issuedAt=date),dict(deviceId=self.device,label='Native lab',publicKey=enc,deviceSigningPublicKey=sig,kind='linked',issuedAt=date)],revocations=[],issuedAt=date)
        self.binding=dict(address=address,rootPin=H(self.root.public_key().public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)),deviceId=self.device,signPin=p['signingPin'],encPin=p['encryptionPin'],appPin=H(unb64(self.app)));self.bindfile=self.local/'binding.json';self.bindfile.write_text(json.dumps(self.binding));self.initial=self.signed(self.payload);self.mfile=self.local/'manifest.json';self.mfile.write_text(json.dumps(self.initial))
    def signed(self,p,key=None):
        text=subprocess.check_output(['node','--input-type=module','-e',"import {canonicalManifestText} from './lib/quantic/manifest-core.mjs';let a='';for await(const c of process.stdin)a+=c;process.stdout.write(canonicalManifestText(JSON.parse(a)))"],input=json.dumps(p).encode(),cwd=HERE);r,s=decode_dss_signature((key or self.root).sign(text,ec.ECDSA(hashes.SHA256())));return dict(format='quantic-identity-manifest',version=1,payload=copy.deepcopy(p),signature=base64.b64encode(r.to_bytes(32,'big')+s.to_bytes(32,'big')).decode())
    def publish(self,i,m,ok=True):
        self.mfile.write_text(json.dumps(m));r=subprocess.run([sys.executable,str(HERE/'anchor_server.py'),'publish-manifest',str(self.nodes[i]['db']),self.id,str(self.mfile)],capture_output=True,timeout=5);self.assertEqual(r.returncode==0,ok,r.stderr.decode())
    def revoked(self):
        p=copy.deepcopy(self.payload);p['sequence']=2;p['devices']=[d for d in p['devices'] if d['deviceId']!=self.device];p['revocations']=[dict(deviceId=self.device,revokedAt=stamp(),reason='compromised')];return self.signed(p)
    def test_signed_revocation_live(self):
        a=self.enter();self.decrypt(a);self.assertEqual(self.counts(),[1]*4);rev=self.revoked()
        for i in (0,1,2):self.publish(i,rev)
        pub=a.q('public');pkt=a.q('seal',recipient=pub['encryption'],message=b64(b'not released'))['packet'];a.request('open',packet=pkt);a.child.prompt(b'[taper OUI] : ',b'OUI');self.assertNotEqual(a.child.p.wait(timeout=12),0);self.assertEqual(a.child.p.stdout.read(),b'');self.reject_start()
    def test_bad_updates_and_downgrade(self):
        rev=self.revoked();bad=copy.deepcopy(rev);bad['signature']=self.initial['signature'];self.publish(0,bad,False)
        fork=copy.deepcopy(self.payload);fork['devices'][1]['label']='Changed';self.publish(0,self.signed(fork),False)
        replacement=copy.deepcopy(self.payload);replacement['sequence']=2;replacement['devices'][1]['deviceSigningPublicKey']=jwk(ec.generate_private_key(ec.SECP256R1()).public_key());self.publish(0,self.signed(replacement),False)
        self.publish(0,self.signed(rev['payload'],ec.generate_private_key(ec.SECP256R1())),False)
        self.publish(0,rev);self.publish(0,self.initial,False);react=copy.deepcopy(self.payload);react['sequence']=3;self.publish(0,self.signed(react),False)
        legacy=LocalProcess(['--broker-software-quorum-lab',*self.args[1:]]);self.addCleanup(legacy.close);legacy.prompt(b' : ',PASSWORD,True);self.assertNotEqual(legacy.p.wait(timeout=8),0);self.assertEqual(legacy.p.stdout.read(),b'')
        a=self.enter();self.decrypt(a);self.close(a);self.assertEqual(self.counts(),[0,1,1,1])

if __name__=='__main__':
    suite=unittest.TestSuite(ManifestQuorum(n) for n in ['test_signed_revocation_live','test_bad_updates_and_downgrade']);raise SystemExit(not unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful())
