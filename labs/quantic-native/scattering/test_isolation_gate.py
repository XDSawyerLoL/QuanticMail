import json, os, pathlib, re, socket, statistics, subprocess, sys, tempfile, time
from isolated_pacer import validate
HERE=pathlib.Path(__file__).resolve().parent
CPUS=sorted(os.sched_getaffinity(0))
def trial(mode,n):
    pc,wc,rc=CPUS[:3]; busy=pc if mode=='shared' else wc
    workers=[]; p=None; orig=os.sched_getaffinity(0)
    try:
        for _ in range(2):workers.append(subprocess.Popen(['taskset','-c',str(busy),sys.executable,'-c','while True: pass'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL))
        with tempfile.TemporaryDirectory() as d,socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:
            s.bind(('127.0.0.1',0));s.settimeout(.15);times=[];wrong=0
            flags=['-target',f'127.0.0.1:{s.getsockname()[1]}','-queue-dir',d,'-period-us','20000','-poll','10ms','-duration','4s','-wait-mode','native']
            cmd=['taskset','-c',str(pc),str(HERE/'QuanticNativePacer_v7_1_linux_amd64')] if mode=='shared' else [sys.executable,str(HERE/'isolated_pacer.py'),str(pc),str(wc),'--']
            p=subprocess.Popen(cmd+flags,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True);os.sched_setaffinity(0,{rc})
            end=time.monotonic()+9
            while time.monotonic()<end:
                try:v,_=s.recvfrom(2048);times.append(time.monotonic_ns());wrong+=len(v)!=168
                except socket.timeout:
                    if p.poll() is not None:break
            out,err=p.communicate(timeout=2)
            if p.returncode:raise RuntimeError(err)
            fields={k:int(v) for k,v in re.findall(r'(planned|sent|missed|write_errors|spacing_skipped|cover_starved)=(\d+)',out)}
            gaps=[(b-a)/1e6 for a,b in zip(times,times[1:])];assert fields['planned']==200 and gaps
            gate=fields['missed']<=2 and len(times)>=198 and wrong==0 and fields['write_errors']==0 and max(gaps)<=60
            return dict(round=n,mode=mode,pacer_cpu=pc,load_cpu=busy,receiver_cpu=rc,received=len(times),wrong_size=wrong,max_gap_ms=round(max(gaps),3),median_gap_ms=round(statistics.median(gaps),3),gate=gate,**fields)
    finally:
        if p is not None and p.poll() is None:p.kill();p.wait()
        for w in workers:w.terminate()
        for w in workers:w.wait(timeout=2)
        os.sched_setaffinity(0,orig)
if __name__=='__main__':
    assert len(CPUS)>=3
    validate(CPUS[0],{CPUS[1]},set(CPUS))
    for cpu,work in [(CPUS[0],{CPUS[0]}),(-1,{CPUS[1]}),(CPUS[0],set())]:
        try:validate(cpu,work,set(CPUS))
        except ValueError:pass
        else:raise AssertionError('invalid placement accepted')
    print(json.dumps({'placement_negative_tests':3,'criteria':'<=2 missed/200; >=198 received; zero size/write errors; max gap <=60ms per trial'}),flush=True)
    for n in range(1,4):
        for mode in (('shared','isolated') if n%2 else ('isolated','shared')):print(json.dumps(trial(mode,n)),flush=True)
