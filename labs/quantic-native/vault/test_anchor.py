"""RC5: actual separate TLS 1.3 checkpoint process and Linux vault process."""
import datetime, hashlib, json, pathlib, shutil, socket, ssl, subprocess, sys, tempfile, unittest, urllib.request, urllib.error
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from test_portable import LocalProcess, Controller, BINARY, PASSWORD, b64, unb64
HERE=pathlib.Path(__file__).resolve().parent

def certs(d):
    now=datetime.datetime.now(datetime.timezone.utc); ca=ec.generate_private_key(ec.SECP256R1()); name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'QV lab CA')])
    def builder(subject,key):return x509.CertificateBuilder().subject_name(subject).issuer_name(name).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-datetime.timedelta(minutes=5)).not_valid_after(now+datetime.timedelta(days=1))
    root=builder(name,ca).add_extension(x509.BasicConstraints(ca=True,path_length=0),True).add_extension(x509.SubjectKeyIdentifier.from_public_key(ca.public_key()),False).add_extension(x509.KeyUsage(False,False,False,False,False,True,True,False,False),True).sign(ca,hashes.SHA256()); (d/'ca.pem').write_bytes(root.public_bytes(serialization.Encoding.PEM))
    pins={}
    for n,usage in [('server',ExtendedKeyUsageOID.SERVER_AUTH),('client',ExtendedKeyUsageOID.CLIENT_AUTH),('wrong',ExtendedKeyUsageOID.CLIENT_AUTH)]:
        k=ec.generate_private_key(ec.SECP256R1()); b=builder(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,n)]),k).add_extension(x509.BasicConstraints(ca=False,path_length=None),True).add_extension(x509.ExtendedKeyUsage([usage]),False).add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca.public_key()),False).add_extension(x509.SubjectKeyIdentifier.from_public_key(k.public_key()),False).add_extension(x509.KeyUsage(True,False,False,False,False,False,False,False,False),True)
        if n=='server': b=b.add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost')]),False)
        c=b.sign(ca,hashes.SHA256());(d/(n+'.pem')).write_bytes(c.public_bytes(serialization.Encoding.PEM)); kp=d/(n+'.key');kp.write_bytes(k.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()));kp.chmod(0o600);pins[n]=c.fingerprint(hashes.SHA256()).hex()
    return pins

class TestAnchor(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.d=pathlib.Path(self.tmp.name); self.local=self.d/'local';self.local.mkdir(mode=0o700);self.authority=self.d/'authority';self.authority.mkdir(mode=0o700);self.vault=self.local/'vault';self.journal=self.local/'journal';self.db=self.authority/'check.db';self.conf=self.local/'anchor.json';self.appkey=Ed25519PrivateKey.generate(); self.app=b64(self.appkey.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw));self.pins=certs(self.authority)
        create=LocalProcess(['--provision-software-anchored-lab',self.vault,self.pins['server']]);self.addCleanup(create.close);create.prompt(b' : ',PASSWORD,True);create.prompt(b' : ',PASSWORD,True);p=create.reply();self.assertEqual(create.p.wait(timeout=5),0);self.args=['--broker-software-anchored-lab',self.vault,p['signingPin'],p['encryptionPin'],self.app,self.journal,self.conf];subprocess.run([str(BINARY),'--init-replay-lab',str(self.journal),p['signingPin'],p['encryptionPin'],self.app],check=True); self.old=self.journal.read_bytes();self.id=hashlib.sha256(self.old).hexdigest()
        subprocess.run([sys.executable,str(HERE/'anchor_server.py'),'init',str(self.db),self.id],check=True);self.old_db=self.db.read_bytes();self.server=None;self.start_server();self.addCleanup(self.stop_server)
    def start_server(self):
        d=self.authority
        self.server=subprocess.Popen([sys.executable,str(HERE/'anchor_server.py'),'serve',str(self.db),'--port','0','--cert',str(d/'server.pem'),'--key',str(d/'server.key'),'--ca',str(d/'ca.pem'),'--client-pin',self.pins['client']],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        self.port=json.loads(self.server.stdout.readline())['port'];self.config()
    def config(self,**kw):
        d=self.authority;c=dict(url=f'https://localhost:{self.port}',serverCA=str(d/'ca.pem'),serverPin=self.pins['server'],clientCert=str(d/'client.pem'),clientKey=str(d/'client.key'));c.update(kw);self.conf.write_text(json.dumps(c));self.conf.chmod(0o600)
    def stop_server(self):
        if self.server is not None:
            self.server.kill();self.server.wait(timeout=5);self.server.stdout.close();self.server.stderr.close();self.server=None
    def enter(self):
        a=Controller(self.args,self.appkey);self.addCleanup(a.child.close);a.unlock();return a
    def reject_start(self):
        a=LocalProcess(self.args);self.addCleanup(a.close);a.prompt(b' : ',PASSWORD,True);self.assertNotEqual(a.p.wait(timeout=8),0);self.assertEqual(a.p.stdout.read(),b'')
    def decrypt(self,a):
        pub=a.q('public'); pkt=a.q('seal',recipient=pub['encryption'],message=b64(b'synthetic'))['packet'];a.request('open',packet=pkt);a.child.prompt(b'[taper OUI] : ',b'OUI');self.assertEqual(unb64(a.child.reply()['message']),b'synthetic');return pkt
    def close(self,a):
        self.assertTrue(a.q('close')['ok']);self.assertEqual(a.child.p.wait(timeout=5),0)
    def query(self,op,p,cert='client'):
        d=self.authority;ctx=ssl.create_default_context(cafile=str(d/'ca.pem'));ctx.minimum_version=ssl.TLSVersion.TLSv1_3;ctx.load_cert_chain(d/(cert+'.pem'),d/(cert+'.key'))
        try:
            with urllib.request.urlopen(urllib.request.Request(f'https://localhost:{self.port}/{op}',data=json.dumps(p).encode(),headers={'Content-Type':'application/json'}),context=ctx,timeout=5) as r:return r.status
        except urllib.error.HTTPError as e:return e.code
    def test_rollback_rewrite_restart_and_dual_rollback_limit(self):
        a=self.enter();pkt=self.decrypt(a);a.child.p.kill();a.child.p.wait(timeout=5);current=self.journal.read_bytes();self.stop_server();self.start_server()
        b=self.enter();self.assertFalse(b.q('open',packet=pkt)['ok']);self.close(b)
        self.journal.write_bytes(self.old);self.reject_start()
        # A fabricated valid local checksum chain with the same count also fails.
        fake=bytes.fromhex('ab'*32);self.journal.write_bytes(self.old+fake+hashlib.sha256(bytes.fromhex(self.id)+fake).digest());self.reject_start()
        self.journal.write_bytes(current);c=self.enter();self.close(c)
        # Explicit counterexample: attacker controls BOTH state domains.
        self.stop_server();self.db.write_bytes(self.old_db);self.journal.write_bytes(self.old);self.start_server();d=self.enter();d.request('open',packet=pkt);d.child.prompt(b'[taper OUI] : ',b'OUI');self.assertTrue(d.child.reply()['ok']);self.close(d)
    def test_wrong_pins_and_cas(self):
        # The same vault cannot be opened by the legacy unanchored mode.
        legacy=LocalProcess(['--broker-software-guarded-lab',*self.args[1:-1]]);self.addCleanup(legacy.close);legacy.prompt(b' : ',PASSWORD,True);self.assertNotEqual(legacy.p.wait(timeout=8),0);self.assertEqual(legacy.p.stdout.read(),b'')
        p=dict(id=self.id,count=0,tail=self.id);self.assertEqual(self.query('check',p),200);self.assertEqual(self.query('check',p,'wrong'),403)
        self.config(serverPin='0'*64);self.reject_start();self.config(clientCert=str(self.authority/'wrong.pem'),clientKey=str(self.authority/'wrong.key'));self.reject_start();self.config()
        self.assertEqual(self.query('advance',{**p,'record':'01'*32}),200);self.assertEqual(self.query('advance',{**p,'record':'02'*32}),409);self.reject_start()
    def test_outage_no_plaintext_no_fallback(self):
        a=self.enter();pub=a.q('public');pkt=a.q('seal',recipient=pub['encryption'],message=b64(b'synthetic'))['packet'];self.stop_server();a.request('open',packet=pkt);a.child.prompt(b'[taper OUI] : ',b'OUI');self.assertNotEqual(a.child.p.wait(timeout=8),0);self.assertEqual(a.child.p.stdout.read(),b'');self.assertEqual(len(self.journal.read_bytes()),len(self.old)+64);self.start_server();self.reject_start()
if __name__=='__main__':unittest.main(verbosity=2)
