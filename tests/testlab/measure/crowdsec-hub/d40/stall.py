#!/usr/bin/env python3
# TEST ONLY: MVP-26 / D40 item 2.4. Two passes of blocked requests from the same clients within one minute: the first
# creates the incidents, then the store stalls (an exclusive SQLite lock from outside), the second pass only adds hits.
#   stall.py <clients> <out.json>
import json, os, re, sqlite3, subprocess, sys, threading, time

HERE = os.path.dirname(os.path.abspath(__file__))
INST = os.path.join(HERE, '..', 'inst.sh')
N, OUT = int(sys.argv[1]), sys.argv[2]
open('/tmp/m26/d40/st.yaml', 'w').write('behaviour:\n  presets: [generic]\n  preset_limits: "off"\n  scenarios:\n    waf_repeat: { mode: observe }\n    path_probing: { mode: observe }\n    aggressive_crawl: { mode: observe }\n')
P = 346
D = '/tmp/m26/i/bl'
e = dict(os.environ, MODE='autoblock', STATE='off', MON='false', HUBURL='http://127.0.0.1:9/none', HUBAUTO='false', EXTRA='/tmp/m26/d40/st.yaml')
subprocess.run(['bash', INST, 'start', 'bl', str(P)], env=e, check=True, capture_output=True)
for f in ('/tmp/m26/d40/m1', '/tmp/m26/d40/m2'):
    if os.path.exists(f):
        os.remove(f)


def rss():
    return int(subprocess.run(['ps', '-o', 'rss=', '-p', open(f'{D}/schild.pid').read().strip()], capture_output=True, text=True).stdout or 0)


def metric():
    m = subprocess.run(['curl', '-s', '-m', '5', f'http://127.0.0.1:{P}11/metrics'], capture_output=True, text=True).stdout
    return {l.split(' ')[0]: float(l.split(' ')[1]) for l in m.splitlines() if l.startswith(('schild_incident_hits_dropped', 'schild_events_dropped', 'schild_requests_total'))}


res = {'clients': N, 'rss_before_kb': rss()}
p = subprocess.Popen(['/tmp/m26/bin/floodtool', 'blocks', '-target', f'http://127.0.0.1:{P}90', '-clients', str(N), '-marker', '/tmp/m26/d40/m1', '-go', '/tmp/m26/d40/m2'], stdout=subprocess.PIPE, text=True)
while not os.path.exists('/tmp/m26/d40/m1'):
    time.sleep(0.02)
    if p.poll() is not None:
        break
res['after_pass1'] = {'rss': rss(), 'metrics': metric(), 'at': time.strftime('%H:%M:%S')}
con = sqlite3.connect(f'{D}/data/schild.db', timeout=30, isolation_level=None)
con.execute('BEGIN EXCLUSIVE')
open('/tmp/m26/d40/m2', 'w').write('x')
sam = []
while p.poll() is None:
    sam.append(rss())
    time.sleep(0.5)
res['flood'] = p.communicate()[0]
res['rss_during_stall_max_kb'] = max(sam) if sam else None
res['during'] = metric()
time.sleep(2)
con.execute('COMMIT')
con.close()
time.sleep(4)
res['after'] = metric()
res['rss_after_kb'] = rss()
c2 = sqlite3.connect(f'{D}/data/schild.db')
res['incidents'] = list(c2.execute('select count(*), sum(count), max(count) from incidents'))
res['log'] = subprocess.run(['grep', '-h', 'incident', f'{D}/schild-1.log'], capture_output=True, text=True).stdout[-600:]
subprocess.run(['bash', INST, 'stop', 'bl'], env=e, capture_output=True)
json.dump(res, open(OUT, 'w'), indent=1)
print(json.dumps(res, indent=0)[:1800])
