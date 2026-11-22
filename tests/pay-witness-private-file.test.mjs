import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,mkdirSync,writeFileSync,symlinkSync,linkSync,chmodSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {generateKeyPairSync,createPublicKey} from 'node:crypto';
import {readWitnessPrivateFileLab,loadWitnessPrivateKeyLab} from '../lib/quantic/pay-witness-private-file-lab.mjs';

test('witness private keys fail closed on symlink, hardlink, broad permissions, oversized and unsafe parent',{skip:process.platform!=='linux'},t=>{
 const dir=mkdtempSync(join(tmpdir(),'quantic-locked-key-'));
 try{
  const privatePem=generateKeyPairSync('ed25519').privateKey.export({type:'pkcs8',format:'pem'});
  const allowed=join(dir,'witness.pem');
  writeFileSync(allowed,privatePem,{mode:0o600});
  assert.deepEqual(readWitnessPrivateFileLab(allowed),Buffer.from(privatePem));
  assert.equal(createPublicKey(loadWitnessPrivateKeyLab(allowed)).asymmetricKeyType,'ed25519');

  const symlink=join(dir,'symlink.pem');
  symlinkSync(allowed,symlink);
  assert.throws(()=>readWitnessPrivateFileLab(symlink),'symlink blocked by O_NOFOLLOW');

  const hardlink=join(dir,'hardlink.pem');
  linkSync(allowed,hardlink);
  assert.throws(()=>loadWitnessPrivateKeyLab(allowed),'original with two links must also be refused');
  assert.throws(()=>readWitnessPrivateFileLab(hardlink));
  rmSync(hardlink);

  chmodSync(allowed,0o644);
  assert.throws(()=>loadWitnessPrivateKeyLab(allowed),'world-readable key must be refused');
  chmodSync(allowed,0o600);

  const shared=join(dir,'shared');
  mkdirSync(shared,{mode:0o777});
  chmodSync(shared,0o777);
  const sharedKey=join(shared,'leak.pem');
  writeFileSync(sharedKey,privatePem,{mode:0o600});
  assert.throws(()=>loadWitnessPrivateKeyLab(sharedKey),'shared parent permits file replacement');
  const tooBig=join(dir,'oversized.pem');
  writeFileSync(tooBig,Buffer.alloc(65537,65),{mode:0o600});
  assert.throws(()=>loadWitnessPrivateKeyLab(tooBig),'64 KiB key cap');
  assert.throws(()=>readWitnessPrivateFileLab(tooBig,{maxBytes:4096}));
  assert.throws(()=>readWitnessPrivateFileLab('relative/path'));
  assert.throws(()=>readWitnessPrivateFileLab(allowed,{maxBytes:524289}));

  const linkedDir=join(dir,'linked-dir');
  symlinkSync(shared,linkedDir);
  assert.throws(()=>readWitnessPrivateFileLab(join(linkedDir,'leak.pem')));
  t.diagnostic('WITNESS_PRIVATE_FILE_HARDENING_V1 '+JSON.stringify({
   sameOwnerRequired:true,privateParentRequired:true,
   noFollow:true,hardlinksRefused:true,worldReadableRefused:true,
   boundedPrivateKey:true,simulationOnly:true}));
 }finally{rmSync(dir,{recursive:true,force:true});}
});
