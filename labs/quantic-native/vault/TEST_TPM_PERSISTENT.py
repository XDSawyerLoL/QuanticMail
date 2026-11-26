"""Interactive Windows hardware acceptance test; synthetic profile only.
Do not use a production identity or real messages. Requires Python 3.
"""
import base64
import json
import os
from pathlib import Path
import queue
import secrets
import subprocess
import threading
import hashlib
import struct
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

HERE = Path(__file__).resolve().parent
EXE = HERE / 'VaultIsolated.exe'

def b64(b): return base64.urlsafe_b64encode(b).decode().rstrip('=')

def run(*args, timeout=120):
    return subprocess.run([str(EXE), *args], input='', text=True,
                          capture_output=True, timeout=timeout)

class Broker:
    def __init__(self, *args, controller=None):
        self.p = subprocess.Popen([str(EXE), *args], stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE, stderr=None, text=True,
                                  encoding='utf-8')
        self.responses = queue.Queue()
        def reader():
            try:
                for line in self.p.stdout:
                    self.responses.put(line)
            finally:
                self.responses.put(None)
        self.thread = threading.Thread(target=reader, daemon=True)
        self.thread.start()
        self.controller = controller
        self.seq = 0
        if controller:
            line = self.responses.get(timeout=120)
            if line is None: raise RuntimeError('Guarded broker refused startup')
            session = json.loads(line)['session']
            self.nonce = base64.urlsafe_b64decode(session+'='*(-len(session)%4))

    def __enter__(self): return self
    def __exit__(self, *_):
        if self.p.poll() is None:
            self.p.stdin.close()
            try: self.p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.p.kill(); self.p.wait(timeout=5)
        self.p.stdout.close()
    def ask(self, op, **kw):
        body = json.dumps(dict(op=op, **kw), separators=(',', ':')).encode()
        if self.controller:
            self.seq += 1
            digest = hashlib.sha256(b'quantic-vault-controller-lab/v1\x00'+self.nonce+struct.pack('>I',self.seq)+body).digest()
            frame = dict(seq=self.seq,body=b64(body),sig=b64(self.controller.sign(digest)))
            body = json.dumps(frame).encode()
        self.p.stdin.write(body.decode()+'\n')
        self.p.stdin.flush()
        line = self.responses.get(timeout=120)
        if line is None: raise RuntimeError('Native process closed; see stderr')
        return json.loads(line)

def main():
    if not __debug__: raise RuntimeError('Do not run tests with Python optimization')
    if os.name != 'nt': raise RuntimeError('A real Windows machine is required')
    if not EXE.is_file(): raise RuntimeError('VaultIsolated.exe missing')
    profile = secrets.token_hex(16)
    # Reserve a separate receipt before provision; even failure identifies the synthetic names.
    receipt = HERE / ('TPM_TEST_'+profile+'.json')
    with receipt.open('x', encoding='utf-8') as f: json.dump({'profile':profile,'state':'provisioning'},f)
    print('Synthetic profile:', profile, flush=True)
    print('Approve creation in the native Windows dialog. No existing keys will be imported.', flush=True)
    r = run('--provision-persistent-lab', profile)
    if r.returncode != 0:
        raise RuntimeError('Provisioning failed; no software fallback: '+r.stderr)
    pins = json.loads(r.stdout)
    if pins['profile'] != profile or pins['backend'] != 'tpm-persistent-lab':
        raise RuntimeError('Unexpected provisioning receipt')
    receipt.write_text(json.dumps(pins, indent=2), encoding='utf-8')
    args = (profile, pins['signingPin'], pins['encryptionPin'])
    controller = Ed25519PrivateKey.generate()
    app = b64(controller.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))
    journal = str((HERE / ('TPM_REPLAY_'+profile+'.bin')).resolve())
    guarded = (*args, app, journal)

    passed = False
    try:
        initialized = run('--init-replay-lab',journal,args[1],args[2],app)
        assert initialized.returncode == 0, initialized.stderr
        with Broker('--broker-guarded-lab', *guarded, controller=controller) as a:
            public = a.ask('public')
            assert public['ok'] and public['backend']=='tpm-persistent-lab-guarded'
            challenge = a.ask('issue')['challenge']
            print('Approve the signature test in the local dialog.', flush=True)
            assert a.ask('prove', challenge=challenge, approved=True)['ok']
            assert not a.ask('prove', challenge=challenge, approved=True)['ok']
            with Broker('--broker-test-software') as sender:
                msg = b64(b'Quantic synthetic restart test, no personal data')
                packet = sender.ask('seal',recipient=public['encryption'],message=msg)['packet']
        with Broker('--broker-guarded-lab', *guarded, controller=controller) as b:
            assert b.ask('public') == public, 'Public keys changed after restart'
            print('Select NO in the next decryption dialog to test local refusal.', flush=True)
            assert not b.ask('open',packet=packet,approved=True)['ok'], 'Native denial bypassed'
            print('Select YES in the next dialog to test decryption after restart.', flush=True)
            assert b.ask('open',packet=packet)['message']==msg, 'Persistent key cannot decrypt'
            assert not b.ask('open',packet=packet)['ok'], 'Replay within process accepted'
        with Broker('--broker-guarded-lab', *guarded, controller=controller) as c:
            assert not c.ask('open',packet=packet)['ok'], 'Replay across restart accepted'
        invalid = '0'*64 if args[1]!='0'*64 else '1'*64
        wrong = run('--broker-guarded-lab', profile, invalid, args[2], app, journal, timeout=30)
        assert wrong.returncode != 0 and 'pin mismatch' in wrong.stderr
        passed = True
    finally:
        print('Approve cleanup of this synthetic profile in the local dialog.', flush=True)
        cleaned = run('--cleanup-persistent-lab', *args)
        if cleaned.returncode != 0:
            print('Cleanup did not complete. Keep receipt:', receipt, cleaned.stderr, flush=True)
            passed = False
        else:
            pins['state']='cleaned';receipt.write_text(json.dumps(pins,indent=2),encoding='utf-8')
    if not passed: raise RuntimeError('Incomplete test or cleanup')
    print('PASS: persistent TPM key pair, signed controller, native consent, cross-restart replay refusal, wrong pin refusal, lab cleanup.')
    print('Not tested: production migration, state rollback resistance, TPM attestation or power loss.')

if __name__=='__main__': main()
