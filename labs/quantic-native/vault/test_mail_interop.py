import base64,json,pathlib,subprocess,unittest
from test_compact_registry import Compact
from test_portable import unb64
HERE=pathlib.Path(__file__).resolve().parent
class MailInterop(Compact):
    def envelope(self,pub):
        return json.loads(subprocess.check_output(['node',str(HERE/'mail_fixture.mjs'),pub['encryption']]))
    def test_browser_wire_and_live_revocation(self):
        a=self.enter();pub=a.q('public');env=self.envelope(pub)
        a.request('mail-open-static-lab',mail=env);a.child.prompt(b'[taper OUI] : ',b'NON');self.assertFalse(a.child.reply()['ok'])
        a.request('mail-open-static-lab',mail=env);a.child.prompt(b'[taper OUI] : ',b'OUI');r=a.child.reply();self.assertTrue(r['ok']);self.assertEqual(json.loads(unb64(r['message'])),{'subject':'interop','body':'synthetic mail only'});self.assertEqual(self.counts(),[1]*4)
        env['ephemeralPublicKey']['ext']=False
        self.assertFalse(a.q('mail-open-static-lab',mail=env)['ok'])
        bad=self.envelope(pub);c=bytearray(base64.b64decode(bad['ciphertext']));c[0]^=1;bad['ciphertext']=base64.b64encode(c).decode()
        a.request('mail-open-static-lab',mail=bad);a.child.prompt(b'[taper OUI] : ',b'OUI');self.assertFalse(a.child.reply()['ok']);self.assertEqual(self.counts(),[1]*4)
        rev=self.revoked();self.publish_lease(rev,(0,1,2));self.wait_lease(rev,(0,1,2));new=self.envelope(pub)
        a.request('mail-open-static-lab',mail=new);a.child.prompt(b'[taper OUI] : ',b'OUI');self.assertNotEqual(a.child.p.wait(timeout=12),0);self.assertEqual(a.child.p.stdout.read(),b'');self.report()
if __name__=='__main__':unittest.main(verbosity=2)
