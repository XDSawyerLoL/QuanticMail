"""Four real Scattering bridges, four TLS witnesses, one synthetic Linux vault."""
import json,pathlib,subprocess,sys,unittest,time
from test_quorum import Quorum as Base
from test_anchor import b64
HERE=pathlib.Path(__file__).resolve().parent
BRIDGE=HERE.parent/'scattering'/'anchor-bridge.mjs'
class IntegratedQuorum(Base):
    def start(self,i):
        super().start(i);n=self.nodes[i];n['direct_port']=n['port']
        n['bridge']=subprocess.Popen(['node',str(BRIDGE),str(n['port']),'--synthetic-loopback-only'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        n['port']=json.loads(n['bridge'].stdout.readline())['port']
    def stop_bridge(self,i):
        n=self.nodes[i];b=n.pop('bridge',None)
        if b is not None:
            b.terminate();out,err=b.communicate(timeout=6)
            if out.strip():
                report=json.loads(out.strip().splitlines()[-1])['stats'];print('carrier',i,json.dumps(report),flush=True)
                self.assertEqual(report['wrongSize'],0)
    def stop(self,i):
        self.stop_bridge(i);super().stop(i)
    def revoke(self,i):
        subprocess.run([sys.executable,str(HERE/'anchor_server.py'),'revoke',str(self.nodes[i]['db']),self.id],check=True,timeout=5)
    def test_all_four_bridges_and_rollback(self):
        a=self.enter();self.decrypt(a);self.close(a);self.assertEqual(self.counts(),[1]*4);time.sleep(.3)
        self.journal.write_bytes(self.old);self.reject_start()
    def test_one_bridge_offline_and_live_revocation(self):
        a=self.enter();self.stop_bridge(0);self.decrypt(a);self.assertEqual(self.counts(),[0,1,1,1]);time.sleep(.3)
        for i in (1,2,3):self.revoke(i)
        pub=a.q('public');pkt=a.q('seal',recipient=pub['encryption'],message=b64(b'never released'))['packet'];a.request('open',packet=pkt);a.child.prompt(b'[taper OUI] : ',b'OUI');self.assertNotEqual(a.child.p.wait(timeout=8),0);self.assertEqual(a.child.p.stdout.read(),b'');self.assertEqual(self.counts(),[0,1,1,1]);self.reject_start()
    def test_signature_gated_by_revocation(self):
        a=self.enter();challenge=a.q('issue')['challenge'];a.request('prove',challenge=challenge,approved=True);a.child.prompt(b'[taper OUI] : ',b'OUI');self.assertTrue(a.child.reply()['ok']);self.assertEqual(self.counts(),[1]*4);time.sleep(.3)
        for i in (0,1,2):self.revoke(i)
        challenge=a.q('issue')['challenge'];a.request('prove',challenge=challenge,approved=True);a.child.prompt(b'[taper OUI] : ',b'OUI');self.assertNotEqual(a.child.p.wait(timeout=8),0);self.assertEqual(a.child.p.stdout.read(),b'');self.assertEqual(self.counts(),[1,1,1,2]);self.reject_start()
if __name__=='__main__':
    suite=unittest.TestSuite(IntegratedQuorum(n) for n in ['test_all_four_bridges_and_rollback','test_one_bridge_offline_and_live_revocation','test_signature_gated_by_revocation'])
    raise SystemExit(not unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful())
