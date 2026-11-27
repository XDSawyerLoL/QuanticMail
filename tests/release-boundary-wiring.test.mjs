import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const root = new URL('../',import.meta.url);
function read(path){return readFileSync(fileURLToPath(new URL(path,root)),'utf8');}
test('Hostinger publication checks legacy policy before exporting and publishing',()=>{
  const text=read('.github/workflows/publish-hostinger-dist.yml');
  const gate=text.indexOf('node scripts/assert-release-boundary.mjs --assert-web');
  const build=text.indexOf('npm run build:hostinger');
  const publish=text.indexOf('git push --force origin hostinger-dist');
  assert.ok(gate>0 && build>gate && publish>build);
  assert.match(text,/out\/QUANTIC_RELEASE_AUDIT\.json/);
});
test('Windows release checks legacy policy before builder and before GitHub publication',()=>{
  const text=read('.github/workflows/desktop-release.yml');
  const gate=text.indexOf('node scripts/assert-release-boundary.mjs --assert-desktop');
  const build=text.indexOf('npm run desktop:dist');
  const publish=text.indexOf('gh release create');
  assert.ok(gate>0 && build>gate && publish>build);
  assert.match(text,/desktop-dist\/QUANTIC_RELEASE_AUDIT\.json/);
});
