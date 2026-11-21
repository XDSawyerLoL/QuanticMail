import json,sqlite3,time,unittest
from scheduled_registry import pack_lease,unpack_lease,ScheduledRegistry,RESPONSE_SIZE,MAX_AGE
class ScheduleLimits(unittest.TestCase):
    def test_fixed_padding(self):
        for data in (b'{}',b'x'*(RESPONSE_SIZE-4)):
            raw=pack_lease(data);self.assertEqual(len(raw),RESPONSE_SIZE);self.assertEqual(unpack_lease(raw),data)
        with self.assertRaises(ValueError):pack_lease(b'x'*(RESPONSE_SIZE-3))
        with self.assertRaises(ValueError):unpack_lease(pack_lease(b'{}')[:-1])
        with self.assertRaises(ValueError):unpack_lease(pack_lease(b'{}')[:-1]+b'x')
    def test_vote_snapshot_age_expiry_and_durable_match(self):
        worker=ScheduledRegistry(None,'a'*64,'id',None)
        with sqlite3.connect(':memory:') as c:
            c.execute('CREATE TABLE signed_manifest (id TEXT,manifest TEXT,denied INTEGER)');c.execute('CREATE TABLE registry_lease (id TEXT,issued INTEGER,expires INTEGER)')
            now=time.time_ns()//1000000;p=dict(issued=now-1000,expires=now+20000,manifest={'test':'synthetic'});r=dict(sequence=1,digest='b'*64,active=True)
            c.execute('INSERT INTO signed_manifest VALUES (?,?,0)',('id',json.dumps(p['manifest'])));c.execute('INSERT INTO registry_lease VALUES (?,?,?)',('id',p['issued'],p['expires']))
            with self.assertRaises(ValueError):worker.vote(c,'id')
            worker.snapshot=(p,r,time.monotonic());v=worker.vote(c,'id');self.assertEqual(v['digest'],'b'*64);self.assertLessEqual(v['expires'],now+int(MAX_AGE*1000)+100)
            with self.assertRaises(ValueError):worker.vote(c,'other')
            worker.snapshot=(p,r,time.monotonic()-MAX_AGE-1)
            with self.assertRaises(ValueError):worker.vote(c,'id')
            worker.snapshot=({**p,'expires':now-1},r,time.monotonic())
            with self.assertRaises(ValueError):worker.vote(c,'id')
            worker.snapshot=(p,r,time.monotonic());c.execute('UPDATE signed_manifest SET denied=1')
            with self.assertRaises(ValueError):worker.vote(c,'id')
            c.execute('UPDATE signed_manifest SET denied=0,manifest=?',('{}',))
            with self.assertRaises(ValueError):worker.vote(c,'id')
        c.close()
    def test_failed_fetch_clears_cache(self):
        class BadFeed:
            def fetch(self):raise OSError('offline')
        w=ScheduledRegistry(BadFeed(),'a'*64,'id',None);w.snapshot=('old',{},time.monotonic());w.refresh();self.assertIsNone(w.snapshot)
if __name__=='__main__':unittest.main(verbosity=2)
