"""Bounded single-host timing probe. Not an anonymity or wire timing test."""
import os, pathlib, socket, subprocess, sys, tempfile, time, statistics, json
HERE=pathlib.Path(__file__).resolve().parent
CPU=min(os.sched_getaffinity(0))

def trial(period,load):
    workers=[]
    try:
        if load:
            for i in range(2):
                workers.append(subprocess.Popen(['taskset','-c',str(CPU),sys.executable,'-c','while True: pass'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL))
        with tempfile.TemporaryDirectory() as d, socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:
            s.bind(('127.0.0.1',0));s.settimeout(.15);times=[];wrong=0
            p=subprocess.Popen(['taskset','-c',str(CPU),str(HERE/'QuanticNativePacer_v7_1_linux_amd64'),'-target',f'127.0.0.1:{s.getsockname()[1]}','-queue-dir',d,'-period-us',str(period),'-poll','10ms','-duration','4s','-wait-mode','native'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
            try:
                end=time.monotonic()+8
                while time.monotonic()<end:
                    try:
                        v,_=s.recvfrom(2048);times.append(time.monotonic_ns());wrong+=len(v)!=168
                    except socket.timeout:
                        if p.poll() is not None:break
                out,err=p.communicate(timeout=2)
                if p.returncode:raise RuntimeError(err)
                gaps=[(b-a)/1e6 for a,b in zip(times,times[1:])]
                assert times and not wrong
                return dict(period_us=period,contending_processes=2 if load else 0,cpu=CPU,received=len(times),wrong_size=wrong,median_gap_ms=round(statistics.median(gaps),3),max_gap_ms=round(max(gaps),3),pacer=out.strip())
            finally:
                if p.poll() is None:p.kill();p.wait()
    finally:
        for w in workers:w.terminate()
        for w in workers:w.wait(timeout=2)
if __name__=='__main__':
    for period in (10000,20000):
        for load in (False,True):print(json.dumps(trial(period,load)),flush=True)
