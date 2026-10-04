#!/usr/bin/env python3
"""Analysis helper for the traffic experiment (docs/ISP_OBSERVABILITY_REPORT.md): trace from scripts/dev-socks-proxy.py --trace + logcat with SEND_AT markers."""
import sys, re, json, math
# usage: analyze.py trace.log logcat.txt start_marker_epoch_ms end_marker_epoch_ms
trace, logcat = sys.argv[1], sys.argv[2]
sends=[int(m.group(1))/1000 for m in re.finditer(r"SEND_AT (\d+)", open(logcat,errors="ignore").read())]
st=re.search(r"EXPERIMENT_START (\d+)", open(logcat,errors="ignore").read()); en=re.search(r"EXPERIMENT_END (\d+)", open(logcat,errors="ignore").read())
t0=int(st.group(1))/1000; t1=int(en.group(1))/1000
rows=[l.split() for l in open(trace) if l.strip()]
ev=[(float(t),d,int(n),int(c)) for t,d,n,c in rows if t0<=float(t)<=t1]
W=10; nwin=int((t1-t0)//W)
up=[0]*nwin; down=[0]*nwin; chunks=[0]*nwin
for t,d,n,c in ev:
    i=int((t-t0)//W)
    if i<nwin:
        if d=="up": up[i]+=n; chunks[i]+=1
        else: down[i]+=n
truth=[any(int((s-t0)//W)==i for s in sends) for i in range(nwin)]
pos=sum(truth); neg=nwin-pos
def best(feature):
    best=0;
    for th in sorted(set(feature)):
        tp=sum(1 for i in range(nwin) if truth[i] and feature[i]>th); tn=sum(1 for i in range(nwin) if not truth[i] and feature[i]<=th)
        best=max(best,(tp/max(pos,1)+tn/max(neg,1))/2)
    return best
conns=len(set(c for _,_,_,c in ev))
print(json.dumps({"windows":nwin,"send_windows":pos,"duration_s":round(t1-t0),"connections":conns,"up_bytes":sum(up),"down_bytes":sum(down),
 "kb_per_hour":round((sum(up)+sum(down))/1024*3600/(t1-t0)),"balanced_accuracy_uplink_bytes":round(best(up),3),"balanced_accuracy_uplink_chunks":round(best(chunks),3)}))
