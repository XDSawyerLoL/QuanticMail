"""Local-admin signed-manifest ingestion; no remote update or reset. Lab only."""
import json,hashlib,pathlib,subprocess,re
HERE=pathlib.Path(__file__).resolve().parent
HEX=re.compile(r'^[0-9a-f]{64}$')
def bounded(path):
    with open(path,'rb') as f: raw=f.read(262145)
    if len(raw)>262144: raise ValueError('manifest too large')
    return json.loads(raw)
def evaluate(binding,current,incoming):
    r=subprocess.run(['node',str(HERE/'manifest_guard.mjs')],input=json.dumps(dict(binding=binding,current=current,incoming=incoming)),text=True,capture_output=True,timeout=2,check=True)
    return json.loads(r.stdout)
def bind(c,identity,binding,manifest):
    if set(binding)!=set('address rootPin deviceId signPin encPin appPin'.split()) or not all(isinstance(binding[x],str) and HEX.fullmatch(binding[x]) for x in ('rootPin','signPin','encPin','appPin')): raise ValueError('bad pins')
    expected=hashlib.sha256(('QV-REPLAY-LAB-V1\n'+binding['signPin']+binding['encPin']+binding['appPin']+'\n').encode()).hexdigest()
    if expected!=identity: raise ValueError('journal binding mismatch')
    if not evaluate(binding,None,manifest)['active']: raise ValueError('device not active')
    c.execute('CREATE TABLE signed_manifest (id TEXT PRIMARY KEY, binding TEXT NOT NULL, manifest TEXT NOT NULL, denied INTEGER NOT NULL CHECK(denied IN (0,1)))')
    c.execute('INSERT INTO signed_manifest VALUES (?,?,?,0)',(identity,json.dumps(binding),json.dumps(manifest)))
def publish(c,identity,manifest):
    row=c.execute('SELECT binding,manifest,denied FROM signed_manifest WHERE id=?',(identity,)).fetchone()
    if not row: raise ValueError('unknown binding')
    b,old,denied=row; r=evaluate(json.loads(b),json.loads(old),manifest)
    if denied and r['active']: raise ValueError('permanent denial')
    c.execute('UPDATE signed_manifest SET manifest=?,denied=? WHERE id=?',(json.dumps(manifest),int(denied or not r['active']),identity))
def active(c,identity):
    row=c.execute('SELECT binding,manifest,denied FROM signed_manifest WHERE id=?',(identity,)).fetchone()
    return bool(row and not row[2] and evaluate(json.loads(row[0]),None,json.loads(row[1]))['active'])
