#!/usr/bin/env python3
"""문지기가 가진(믿는) 검사기 — 원본 저장소의 사본을 실행하지 않는다."""
import sys
text = open(sys.argv[1], encoding='utf-8').read()
if '<<CRASH>>' in text:                      # 도구 장애 흉내
    raise RuntimeError('checker crashed')
bad = [w for w in ('[확인필요]',) if w in text]
print('fail: ' + ', '.join(bad) if bad else 'ok')
sys.exit(1 if bad else 0)
