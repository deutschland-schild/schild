#!/usr/bin/env python3
# TEST ONLY: copy check over the visible page texts (*-texts.txt) of the D36 re-measurement.
# Counts hits of words the rules forbid or flag (AGENTS.md rule 6) and English UI strings.
import re, sys, glob, json, collections
files = sorted(glob.glob(sys.argv[1] + '/*-texts.txt'))
pats = {
  'Sie (address)': r'(?<![.!?]\s)\b(Sie|Ihnen|Ihr|Ihre|Ihren|Ihrem|Ihrer)\b',
  'anonym': r'anonym',
  'geschützt': r'geschützt',
  'sicher': r'\bsicher\w*',
  'fear': r'\b(gefährlich\w*|Gefahr\w*|Bedrohung\w*|Hacker\w*|dringend|sofort handeln|Alarmstufe|kritisch\w*|Panik)\b',
  'Tech-Coach': r'Tech-Coach|TECH-Coach|Tech Coach',
  'Styleguide/Entwicklung': r'Styleguide|Entwicklung',
  'non-release': r'non-release|test keys',
  'raw behaviour reason': r'behaviour [a-z_]+:',
  'English words': r'\b(the|and|with|blocked|request|requests|error|failed|unknown|attack|Detected|Injection|Attempt|Remote|Inbound|Anomaly|Score|Exceeded)\b',
  '10 Sekunden': r'nach etwa 10 Sekunden',
  'gesperrt': r'\bgesperrt\b',
}
out = {}
for f in files:
  lines = open(f, encoding='utf-8').read().split('\n')
  page = '?'
  res = collections.defaultdict(list)
  for ln in lines:
    if ln.startswith('===== '):
      page = ln.strip('= ')
      continue
    for k, p in pats.items():
      for m in re.finditer(p, ln):
        res[k].append((page, ln.strip()[:200]))
  out[f.split('/')[-1]] = {k: {'n': len(v), 'unique_lines': sorted(set(x[1] for x in v))[:40]} for k, v in res.items()}
json.dump(out, open(sys.argv[2], 'w'), ensure_ascii=False, indent=1)
for f, r in out.items():
  print(f, {k: v['n'] for k, v in r.items()})
