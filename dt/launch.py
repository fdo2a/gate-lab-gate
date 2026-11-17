#!/usr/bin/env python3
"""검사기 실행 틀: 검사기를 그대로 돌리되, 그동안 **어느 파일의 코드가 실행됐는지**를 적는다.

  launch.py <믿는 코드 루트> <보고 파일> <검사기 경로> [검사기 인자…]

끝날 때 불러온 모듈의 파일과 exec/compile 된 코드의 파일 이름을 훑어, 믿는 코드 루트·파이썬 표준 위치 밖의 것이 있으면
보고 파일에 한 줄씩 적는다. 「심어 둔 파일이 흔적을 남겼는가」가 아니라 「믿는 곳 밖의 코드가 하나라도 실행됐는가」를 본다."""
import os, runpy, sys, sysconfig

code_root, report, script = sys.argv[1], sys.argv[2], sys.argv[3]
TRUSTED = tuple(os.path.realpath(p) + os.sep for p in {code_root, os.path.dirname(os.path.abspath(__file__)), sys.base_prefix, sys.prefix,
                                                         sysconfig.get_paths()['stdlib'], sysconfig.get_paths()['platstdlib']} if p)
seen = set()


def outside(path):
    if not path or path.startswith('<'):
        return False
    return not (os.path.realpath(path) + os.sep).startswith(TRUSTED) and not os.path.realpath(path).startswith(TRUSTED)


def hook(event, args):
    if event == 'exec' and args:
        name = getattr(args[0], 'co_filename', None)
        if outside(name):
            seen.add('exec:' + os.path.realpath(name))
    elif event == 'import' and len(args) > 1 and args[1] and outside(args[1]):
        seen.add('import:' + os.path.realpath(args[1]))


sys.addaudithook(hook)
sys.argv = [script] + sys.argv[4:]
sys.path[0] = os.path.dirname(script)          # 검사기를 직접 실행했을 때와 같은 첫 경로
try:
    runpy.run_path(script, run_name='__main__')
finally:
    for m in list(sys.modules.values()):
        f = getattr(m, '__file__', None)
        if outside(f):
            seen.add('module:' + os.path.realpath(f))
    if seen:
        with open(report, 'a', encoding='utf-8') as fh:
            for s in sorted(seen):
                fh.write(s + '\n')
