"""Real Go vault -> Scattering carrier -> Python authority; disposable loopback."""
import json, pathlib, subprocess, unittest, time, sqlite3
from test_anchor import TestAnchor as Base, PASSWORD, LocalProcess, b64, unb64
BRIDGE=pathlib.Path(__file__).resolve().parent.parent/'scattering'/'anchor-bridge.mjs'
class Integrated(Base):
    def start_server(self):
        super().start_server(); self.direct_port=self.port
        self.bridge=subprocess.Popen(['node',str(BRIDGE),str(self.direct_port),'--synthetic-loopback-only'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        self.port=json.loads(self.bridge.stdout.readline())['port'];self.config();self.reports=getattr(self,'reports',[])
    def stop_bridge(self):
        b=getattr(self,'bridge',None)
        if b is not None:
            b.terminate();out,err=b.communicate(timeout=6);self.bridge=None
            if out.strip():
                r=json.loads(out.strip().splitlines()[-1])['stats']; self.reports.append(r);print('carrier stats:',json.dumps(r),flush=True)
                self.assertEqual(r['wrongSize'],0)
    def stop_server(self):
        self.stop_bridge();super().stop_server()
    def test_integrated_replay(self):
        a=self.enter();pkt=self.decrypt(a);
        with sqlite3.connect(self.db) as db:self.assertEqual(db.execute("SELECT count FROM checkpoint").fetchone()[0],1)
        a.child.p.kill();a.child.p.wait(timeout=5);time.sleep(.3)
        b=self.enter();self.assertFalse(b.q('open',packet=pkt)['ok']);self.close(b);self.stop_bridge();self.assertGreaterEqual(self.reports[-1]['connections'],3);self.assertGreater(min(self.reports[-1]['datagrams']),0)
    def test_integrated_no_fallback(self):
        a=self.enter();pub=a.q('public');pkt=a.q('seal',recipient=pub['encryption'],message=b64(b'synthetic'))['packet'];self.stop_bridge()
        a.request('open',packet=pkt);a.child.prompt(b'[taper OUI] : ',b'OUI');self.assertNotEqual(a.child.p.wait(timeout=8),0);self.assertEqual(a.child.p.stdout.read(),b'')
        self.assertEqual(len(self.journal.read_bytes()),len(self.old)+64)
    def test_integrated_rollback(self):
        a=self.enter();self.decrypt(a);self.close(a);time.sleep(.3)
        self.journal.write_bytes(self.old);self.reject_start();self.stop_bridge()
        self.assertGreaterEqual(self.reports[-1]['connections'],3)
    def test_integrated_server_pin(self):
        self.config(serverPin='0'*64);self.reject_start()
    def test_integrated_pin(self):
        self.config(clientCert=str(self.authority/'wrong.pem'),clientKey=str(self.authority/'wrong.key'));self.reject_start();self.stop_bridge();self.assertGreater(self.reports[-1]['connections'],0)
if __name__=='__main__':
    suite=unittest.TestSuite(Integrated(n) for n in ['test_integrated_replay','test_integrated_no_fallback','test_integrated_pin','test_integrated_rollback','test_integrated_server_pin'])
    raise SystemExit(not unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful())
