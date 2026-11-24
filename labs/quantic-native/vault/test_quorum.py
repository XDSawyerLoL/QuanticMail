"""Four actual independently keyed local TLS/SQLite processes; synthetic lab only."""
import hashlib,json,pathlib,subprocess,sys,tempfile,unittest,sqlite3
from test_anchor import TestAnchor,certs,PASSWORD,LocalProcess,Controller,BINARY,b64,unb64
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
HERE=pathlib.Path(__file__).resolve().parent
class Quorum(unittest.TestCase):
    enter=TestAnchor.enter;reject_start=TestAnchor.reject_start;decrypt=TestAnchor.decrypt;close=TestAnchor.close
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.d=pathlib.Path(self.tmp.name); self.local=self.d/'local';self.local.mkdir(mode=0o700)
        self.vault=self.local/'vault';self.journal=self.local/'journal';self.conf=self.local/'quorum.json';self.appkey=Ed25519PrivateKey.generate();self.app=b64(self.appkey.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw));self.nodes=[]
        self.addCleanup(self.stop_all)
        for i in range(4):
            d=self.d/str(i);d.mkdir(mode=0o700);self.nodes.append(dict(d=d,pins=certs(d),db=d/'check.db',proc=None))
        pin=hashlib.sha256(b'quantic-anchor-quorum-lab/v1\0' + b'3-of-4\0'+''.join(sorted(n['pins']['server'] for n in self.nodes)).encode()).hexdigest();self.pin=pin
        create=LocalProcess(['--provision-software-quorum-lab',self.vault,pin]);self.addCleanup(create.close);create.prompt(b' : ',PASSWORD,True);create.prompt(b' : ',PASSWORD,True);p=create.reply();self.assertEqual(create.p.wait(timeout=5),0)
        self.args=['--broker-software-quorum-lab',self.vault,p['signingPin'],p['encryptionPin'],self.app,self.journal,self.conf];subprocess.run([str(BINARY),'--init-replay-lab',str(self.journal),p['signingPin'],p['encryptionPin'],self.app],check=True);self.old=self.journal.read_bytes();self.id=hashlib.sha256(self.old).hexdigest()
        for i,n in enumerate(self.nodes):
            subprocess.run([sys.executable,str(HERE/'anchor_server.py'),'init',str(n['db']),self.id],check=True);n['old']=n['db'].read_bytes();self.start(i)
        self.config()
    def start(self,i):
        n=self.nodes[i];d=n['d'];n['proc']=subprocess.Popen([sys.executable,str(HERE/'anchor_server.py'),'serve',str(n['db']),'--port','0','--cert',str(d/'server.pem'),'--key',str(d/'server.key'),'--ca',str(d/'ca.pem'),'--client-pin',n['pins']['client']],stdout=subprocess.PIPE,stderr=subprocess.PIPE);n['port']=json.loads(n['proc'].stdout.readline())['port']
    def stop(self,i):
        n=self.nodes[i];p=n['proc']
        if p is not None:p.kill();p.wait(timeout=5);p.stdout.close();p.stderr.close();n['proc']=None
    def stop_all(self):
        for i in range(len(self.nodes)):self.stop(i)
    def config(self):
        self.configs=[dict(url=f'https://localhost:{n["port"]}',serverCA=str(n['d']/'ca.pem'),serverPin=n['pins']['server'],clientCert=str(n['d']/'client.pem'),clientKey=str(n['d']/'client.key')) for n in self.nodes];self.write_configs(self.configs)
    def write_configs(self,c):self.conf.write_text(json.dumps(c));self.conf.chmod(0o600)
    def restore(self,i):self.stop(i);self.nodes[i]['db'].write_bytes(self.nodes[i]['old']);self.start(i);self.config()
    def counts(self):
        out=[]
        for n in self.nodes:
            with sqlite3.connect(n['db']) as c:out.append(c.execute('SELECT count FROM checkpoint').fetchone()[0])
        return out
    def test_one_rollback_blocked_two_split_three_limit(self):
        a=self.enter();pkt=self.decrypt(a);self.close(a);self.assertEqual(self.counts(),[1]*4);current=self.journal.read_bytes()
        self.restore(0);self.journal.write_bytes(self.old);self.reject_start();self.journal.write_bytes(current);b=self.enter();self.assertFalse(b.q('open',packet=pkt)['ok']);self.close(b)
        self.restore(1);self.journal.write_bytes(self.old);self.reject_start();self.journal.write_bytes(current);self.reject_start()
        # Three rollback domains compromised: explicit counterexample, not a guarantee.
        self.restore(2);self.journal.write_bytes(self.old);c=self.enter();c.request('open',packet=pkt);c.child.prompt(b'[taper OUI] : ',b'OUI');self.assertTrue(c.child.reply()['ok']);self.close(c)
    def test_one_offline_ok_two_offline_refuse_release(self):
        self.stop(0);a=self.enter();self.decrypt(a);self.assertEqual(self.counts(),[0,1,1,1]);self.stop(1);pub=a.q('public');pkt=a.q('seal',recipient=pub['encryption'],message=b64(b'not released'))['packet'];a.request('open',packet=pkt);a.child.prompt(b'[taper OUI] : ',b'OUI');self.assertNotEqual(a.child.p.wait(timeout=8),0);self.assertEqual(a.child.p.stdout.read(),b'');self.assertEqual(self.counts(),[0,1,2,2]);self.reject_start()
    def test_restart_and_no_downgrade(self):
        a=self.enter();pkt=self.decrypt(a);a.child.p.kill();a.child.p.wait(timeout=5);self.stop_all()
        for i in range(4):self.start(i)
        self.config();b=self.enter();self.assertFalse(b.q('open',packet=pkt)['ok']);self.close(b)
        legacy=LocalProcess(['--broker-software-guarded-lab',*self.args[1:-1]]);self.addCleanup(legacy.close);legacy.prompt(b' : ',PASSWORD,True);self.assertNotEqual(legacy.p.wait(timeout=8),0)
        # Substitute a distinct new group member: authenticated vault refuses the new group.
        d=self.d/'replacement';d.mkdir(mode=0o700);p=certs(d);cfg=self.configs.copy();cfg[0]=dict(url='https://localhost:1',serverCA=str(d/'ca.pem'),serverPin=p['server'],clientCert=str(d/'client.pem'),clientKey=str(d/'client.key'));self.write_configs(cfg);self.reject_start()
    def test_duplicate_member_refused(self):
        self.write_configs([self.configs[0]]*4);r=subprocess.run([str(BINARY),*map(str,self.args)],capture_output=True,timeout=5);self.assertNotEqual(r.returncode,0);self.assertIn(b'duplicate',r.stderr)
if __name__=='__main__':unittest.main(verbosity=2)
