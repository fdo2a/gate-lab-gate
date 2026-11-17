#!/usr/bin/env python3
"""문지기가 가진(믿는) 검사기. 글에 `data-close="N"` 이 있으면 자료의 종가와 같아야 한다.
자료가 없으면 「통과」가 아니라 입력 누락(종료 코드 3)이다."""
import json, os, re, sys
text = open(sys.argv[1], encoding='utf-8').read()
data_dir = sys.argv[2]
if '<<CRASH>>' in text:
    raise RuntimeError('checker crashed')
bad = [w for w in ('[확인필요]',) if w in text]
m = re.search(r'data-close="([0-9.]+)"', text)
if m:
    p = os.path.join(data_dir, 'close.json')
    if not os.path.isfile(p):
        print('input_missing: close.json')
        sys.exit(3)
    if float(m.group(1)) != float(json.load(open(p))['close']):
        bad.append('close %s != data %s' % (m.group(1), json.load(open(p))['close']))
print('fail: ' + ', '.join(bad) if bad else 'ok')
sys.exit(1 if bad else 0)
