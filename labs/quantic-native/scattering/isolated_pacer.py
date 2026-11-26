"""Explicit Linux CPU placement, not exclusive reservation or real-time guarantee."""
import os,pathlib,sys

def validate(cpu,work,allowed):
    if cpu not in allowed or not work or not work <= allowed or cpu in work:
        raise ValueError('invalid or overlapping CPU placement')

if __name__=='__main__':
    if len(sys.argv)<5 or sys.argv[3]!='--':raise SystemExit('expected PACER_CPU WORKLOAD_CPUS -- pacer flags')
    try:
        cpu=int(sys.argv[1]);work=set(map(int,sys.argv[2].split(',')))
        validate(cpu,work,os.sched_getaffinity(0));os.sched_setaffinity(0,{cpu})
        if os.sched_getaffinity(0)!={cpu}:raise ValueError('affinity mismatch')
    except (ValueError,OSError,AttributeError) as e:raise SystemExit(f'placement refused: {e}')
    p=pathlib.Path(__file__).resolve().with_name('QuanticNativePacer_v7_1_linux_amd64')
    os.execv(str(p),[str(p),*sys.argv[4:]])
