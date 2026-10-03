#!/usr/bin/env bash
# Re-run the 48-prompt test set through the live ml-guard + current regex rules. Usage: V=3 bash docs/evaluation/eval_layered.sh
# Results go to data/eval-results-bedrock-v$V.json (the repo is mounted read-only in the console).
cd "$(dirname "$0")/../.." || exit 1
docker compose exec -T -e V="${V:-?}" console python3 - <<'PY'
import json, re, urllib.request, unicodedata
rules = [r for r in json.load(open('/gw/data/guardrails.json'))['rules'] if r['enabled'] and 'kiro' in r['applies_to']]
NORM = {**{c: c - 0xFEE0 for c in range(0xFF01, 0xFF5F)}, **{0x0E50 + d: 0x30 + d for d in range(10)}, 0x3000: 0x20,
        0x200B: None, 0x200C: None, 0x200D: None, 0x2060: None, 0xFEFF: None}
def rx(t):
    t = t.translate(NORM)
    return any(re.search(r['pattern'], t, re.I if r.get('case_insensitive') else 0) for r in rules)
def ml(t):
    req = urllib.request.Request('http://172.30.0.40:8080/check', data=json.dumps({'text': t}).encode(), headers={'Content-Type': 'application/json'})
    with urllib.request.urlopen(req, timeout=10) as r: d = json.load(r)
    return d['action'] == 'block', d['policies'], d['latency_ms']
items = [json.loads(l) for l in open('/gw/docs/evaluation/testset.jsonl')]
m = {k: dict(tp=0, fp=0, fn=0, tn=0) for k in ('regex', 'bedrock', 'layered')}
lat, fps, fns, out = [], [], [], []
for it in items:
    r = rx(it['text']); b, pol, ms = ml(it['text']); lat.append(ms); L = r or b
    exp = it['expect'] == 'block'
    for k, v in (('regex', r), ('bedrock', b), ('layered', L)):
        m[k]['tp' if v and exp else 'fp' if v else 'fn' if exp else 'tn'] += 1
    if L and not exp: fps.append(f"{it['id']} {pol}")
    if exp and not L: fns.append(f"{it['id']} ({it['kind']})")
    out.append({'id': it['id'], 'kind': it['kind'], 'expect': it['expect'], 'regex': r, 'bedrock': b, 'policies': pol, 'ms': ms})
lat.sort()
for k, v in m.items():
    p = v['tp'] / max(1, v['tp'] + v['fp']); rc = v['tp'] / max(1, v['tp'] + v['fn'])
    print(f"{k:8} precision {p:.2f} recall {rc:.2f}  {v}")
attacks = [o for o in out if o['kind'] == 'prompt-attack']
print('prompt-attack items caught by layered:', sum(o['regex'] or o['bedrock'] for o in attacks), '/', len(attacks))
print('false blocks:', fps); print('misses:', fns)
print(f"bedrock latency p50 {lat[len(lat)//2]} ms  p95 {lat[int(len(lat)*0.95)]} ms  n={len(lat)}")
json.dump({'guardrail_version': __import__('os').environ.get('V','?'), 'metrics': m, 'false_blocks': fps, 'misses': fns, 'items': out}, open('/gw/data/eval-results-bedrock-v%s.json' % __import__('os').environ.get('V', 'x'), 'w'), indent=1)
PY
