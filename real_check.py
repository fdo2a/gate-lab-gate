#!/usr/bin/env python3
"""실제 검사기 격리 시험. 원본 저장소(bare git)에서 **자료만** 꺼내 data/ 에 두고, 검사 코드는 문지기의 고정 사본
(trusted_real/)에서만 실행한다. data/ 에는 「실행되면 흔적을 남기는」 파일을 일부러 심는다."""
import hashlib, json, os, subprocess, sys

src_git, commit, date, cycle, work = sys.argv[1:6]
HERE = os.path.dirname(os.path.abspath(__file__))
code = os.path.join(HERE, 'trusted_real')
data, datadir, mark = os.path.join(work, 'data'), os.path.join(work, 'datadir'), os.path.join(work, 'pwned')
SKIP = ('scripts/', 'config/', '.github/', '.claude/')


def git(*a):
    return subprocess.run(['git', '--git-dir', src_git, *a], capture_output=True, check=True).stdout


n = skipped = 0
for line in git('ls-tree', '-r', '-z', commit).decode('utf-8', 'surrogateescape').split('\0'):
    if not line:
        continue
    meta, path = line.split('\t', 1)
    mode, typ, sha = meta.split()
    parts = path.split('/')
    if typ != 'blob' or mode not in ('100644', '100755') or path.startswith(SKIP) or '..' in parts or path.startswith('/'):
        skipped += 1
        continue
    dst = os.path.join(data, path)
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    with open(dst, 'wb') as fh:
        fh.write(git('cat-file', 'blob', sha))
    n += 1
print('data files %d, excluded %d (code, config, symlinks, submodules)' % (n, skipped))
subprocess.run(['cp', '-R', os.path.join(code, 'config'), os.path.join(data, 'config')], check=True)   # 믿는 설정 사본

rec = json.load(open(os.path.join(data, 'verification', 'us', date + '.json'), encoding='utf-8'))
post = os.path.join(data, 'posts', date + '.html')
for f in rec['inputs']['files']:
    key, _, rel = f['path'][1:].partition('>/')
    ref = f['ref']
    if ref.startswith('repo:'):
        raw = open(os.path.join(data, ref[5:]), 'rb').read()
    elif ref.startswith('git:'):
        _, c, p = ref.split(':', 2)
        raw = git('show', c + ':' + p)
    elif rel.endswith('morning_brief_%s.html' % date):
        raw = open(post, 'rb').read()
    else:
        continue
    assert hashlib.sha256(raw).hexdigest() == f['sha256'], f['path']
    dst = os.path.join(datadir, rel)
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    open(dst, 'wb').write(raw)
print('post sha256 matches record:', hashlib.sha256(open(post, 'rb').read()).hexdigest() == rec['post']['sha256'])

evil = "import os\nopen(os.environ.get('MARK', '/tmp/pwned'), 'a').write(__file__ + '\\n')\n"
planted = ['sitecustomize.py', 'usercustomize.py', 'json.py', 'html.py', 're.py', 'conftest.py', 'data/json.py',
           'posts/sitecustomize.py', 'research/us/json.py', 'verification/__init__.py', 'common.py', 'us.py', 'verification.py']
for rel in planted:
    p = os.path.join(data, rel)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    open(p, 'w').write(evil)
for rel in ('sitecustomize.py', 'json.py', 'html.py'):
    open(os.path.join(datadir, rel), 'w').write(evil)
print('planted %d hostile modules in the data tree' % (len(planted) + 3))

cfg = json.load(open(os.path.join(code, 'config', 'prepub_gates.json'), encoding='utf-8'))
sub = {'html': post, 'datadir': datadir, 'date': date, 'cycle': cycle, 'tg': os.path.join(datadir, 'telegram.json'), 'repo': data}
env = {'PATH': '/usr/bin:/bin', 'HOME': os.path.join(work, 'home'), 'MARK': mark}
bad = ran = 0
for g in cfg['markets']['us']['gates']:
    if 'argv' not in g:
        continue
    argv = [a.format(**sub) for a in g['argv']]
    p = subprocess.run([sys.executable, os.path.join(code, argv[0]), *argv[1:]], capture_output=True, text=True,
                       cwd=data, env=env, timeout=180)
    ran += 1
    bad += p.returncode != 0
    print('%-22s required=%-5s exit=%d %s' % (g['name'], g.get('required'), p.returncode,
                                           (p.stderr.strip().splitlines() or [''])[-1][:100] if p.returncode else ''))
executed = sorted(set(open(mark).read().split())) if os.path.exists(mark) else []
print('RESULT gates run=%d nonzero=%d hostile modules executed=%d' % (ran, bad, len(executed)))
for e in executed:
    print('  EXECUTED: ' + e)
sys.exit(1 if bad or executed else 0)
