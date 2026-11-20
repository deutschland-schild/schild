#!/usr/bin/env python3
# TEST ONLY: copy check over the string literals of a built dashboard bundle (evening measurement 2026-10-29).
#   python3 -I bundlecheck.py <dist-dir> <out.json>
import re, sys, glob, json, collections
pats = {
  'Sie (address)': r'(?<![.!?]\s)\b(Sie|Ihnen|Ihr|Ihre|Ihren|Ihrem|Ihrer)\b',
  'anonym': r'anonym',
  'geschützt': r'geschützt',
  'sicher': r'\bsicher\w*',
  'fear': r'\b(gefährlich\w*|Gefahr\w*|Bedrohung\w*|Hacker\w*|dringend|sofort handeln|Alarmstufe|kritisch\w*|Panik)\b',
  'Tech-Coach': r'Tech-Coach|Tech Coach',
  'hätte gesperrt': r'[Hh]ätte(n)? gesperrt|gesperrt hätte',
  'hätte (any)': r'[Hh]ätte\w*',
  'Erkannt': r'Erkannt',
  'Styleguide': r'[Ss]tyleguide',
  'non-release': r'non-release|test keys',
  '10 Sekunden': r'nach etwa 10 Sekunden',
}
lit = re.compile(r'"((?:[^"\\\n]|\\.){3,400})"|`((?:[^`\\]|\\.){3,600})`|\'((?:[^\'\\\n]|\\.){3,400})\'')
res = collections.defaultdict(list)
for f in sorted(glob.glob(sys.argv[1] + '/assets/*.js')):
  src = open(f, encoding='utf-8').read()
  for m in lit.finditer(src):
    s = next(g for g in m.groups() if g is not None)
    if not re.search(r'[äöüÄÖÜß]|\b(der|die|das|und|nicht|du|dein|deine)\b', s): continue
    for k, p in pats.items():
      if re.search(p, s): res[k].append((f.split('/')[-1], s[:220]))
out = {k: {'n': len(v), 'strings': sorted(set(x[1] for x in v))} for k, v in res.items()}
json.dump(out, open(sys.argv[2], 'w'), ensure_ascii=False, indent=1)
for k, v in out.items(): print(k, v['n'])
