#!/usr/bin/env python3
"""자료 신뢰 경로 시험 묶음. 사례마다 (루틴이 낸 것, 스냅샷 모습)을 만들고 judge 를 불러 기대와 견준다.

  cases.py --op-git <운영 저장소 bare git> --snapshots <자료 저장소의 snapshots/> --out <디렉터리> [--snap-ref <자료 저장소 커밋>]

「루틴이 낸 것」은 운영 저장소의 발행 커밋을 대역으로 쓴다(글·루틴 상태·연구 원장). 스냅샷 모습을 바꾸는 사례는
수집 쪽에서 일어날 수 있는 일(파일을 못 받음, 어제 파일이 남음, 정정판 추가)을 믿는 쪽에서 흉내 낸 것이다.
"""
import argparse, copy, hashlib, json, os, re, shutil, subprocess, sys, tempfile
from multiprocessing import Pool

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import judge_real as J  # noqa: E402

DATE, PREV = '2026-11-16', '2026-11-13'
SUB = {'us': {'commit': '3378e19652bbd5fdfef8281d4b33ad7fe18a4cb5', 'post': 'posts/2026-11-16.html', 'cycle': 'us-2026-11-16-daily-cycle',
              'state_prev': ('e9ef1a8394b4ae95dd9a7e663f22ac38b68096ff', 'data/macro.json')},
       'kr': {'commit': '1b2e0050024159ab55b828d57d19e8c9539a2eab', 'post': 'kr/posts/2026-11-16.html', 'cycle': 'kr-2026-11-16-cycle'}}
EVIL = "import os\nopen(os.environ.get('MARK', '/tmp/pwned'), 'a').write(__file__ + '\\n')\n"
PLANT = ['sitecustomize.py', 'usercustomize.py', 'json.py', 'html.py', 're.py', 'conftest.py', 'common.py', 'us.py', 'kr.py',
         'verification.py', 'fund.py', 'research/json.py', 'research/{m}/sitecustomize.py', 'research/{m}/__init__.py',
         'posts/sitecustomize.py', 'scripts/check_numbers.py', 'scripts/common/__init__.py', 'config/prepub_gates.json']


def git(*a):
    return subprocess.run(['git', '--git-dir', os.environ['DT_OP_GIT'], *a], capture_output=True, check=True).stdout


def sha(b):
    return hashlib.sha256(b).hexdigest()


def submission(m, root):
    """루틴이 낸 것에서 받는 것만 꺼낸다 — 글, 루틴 상태, 연구 원장(과 미국의 이전 글). 악성 파일을 함께 심는다."""
    c = SUB[m]['commit']
    post = git('cat-file', 'blob', '%s:%s' % (c, SUB[m]['post']))
    src = os.path.join(root, 'sub-src-' + m)
    if not os.path.isdir(src):
        want = ['research/' + m] + (['posts'] if m == 'us' else [])
        for ent in git('ls-tree', '-r', '-z', c, '--', *want).decode('utf-8', 'surrogateescape').split('\0'):
            if not ent:
                continue
            meta, path = ent.split('\t', 1)
            mode, typ, h = meta.split()
            if typ != 'blob' or mode not in ('100644', '100755') or '..' in path.split('/'):
                continue
            dst = os.path.join(src, path)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            open(dst, 'wb').write(git('cat-file', 'blob', h))
        for rel in PLANT:
            p = os.path.join(src, rel.format(m=m))
            os.makedirs(os.path.dirname(p), exist_ok=True)
            open(p, 'w').write(EVIL)
    if m == 'us':
        pc, pp = SUB[m]['state_prev']
        state = {'datadir/macro_next.json': git('cat-file', 'blob', '%s:data/macro.json' % c),
                 'datadir/macro.json': git('cat-file', 'blob', '%s:%s' % (pc, pp))}
    else:
        b = git('cat-file', 'blob', '%s:kr/data/kr_stance.json' % c)
        state = {'datadir/kr_stance.json': b, 'stance_next/kr_stance_next.json': b}
    return post, {'routine_state': state, 'src': src}


# ── 스냅샷 모습 만들기 ────────────────────────────────────────────────────

def view(snaps, tmp, m, edit=None):
    """snapshots/<m>/<DATE> 를 복사하고 edit(dir) 로 바꾼다. edit 는 수집기가 했을 법한 일만 한다."""
    root = os.path.join(tmp, 'snap')
    shutil.copytree(os.path.join(snaps, m, DATE), os.path.join(root, m, DATE))
    if edit:
        edit(os.path.join(root, m, DATE))
    return root


def reseal(base, v=1):
    """파일을 바꾼 뒤 수집기가 했을 것처럼 목록·색인의 해시를 다시 적는다."""
    vdir = os.path.join(base, 'v%d' % v)
    man = json.load(open(os.path.join(vdir, 'manifest.json'), encoding='utf-8'))
    keep = []
    for f in man['files']:
        p = os.path.join(vdir, 'files', f['path'])
        if os.path.isfile(p):
            b = open(p, 'rb').read()
            f.update(sha256=sha(b), bytes=len(b))
            keep.append(f)
    man['files'] = keep
    raw = json.dumps(man, ensure_ascii=False, indent=1, sort_keys=True).encode()
    open(os.path.join(vdir, 'manifest.json'), 'wb').write(raw)
    idx = json.load(open(os.path.join(base, 'index.json'), encoding='utf-8'))
    for x in idx['versions']:
        if x['v'] == v:
            x['manifest_sha256'] = sha(raw)
    open(os.path.join(base, 'index.json'), 'w', encoding='utf-8').write(json.dumps(idx, ensure_ascii=False, indent=1, sort_keys=True))


def drop(path):
    def f(base):
        os.remove(os.path.join(base, 'v1', 'files', path))
        reseal(base)
    return f


def swap_from_prev(snaps, m, paths):
    """어제(PREV) 스냅샷의 파일과 그 수집 기록을 오늘 자리에 둔다 — 수집이 실패해 어제 것이 남은 상황."""
    def f(base):
        pv = os.path.join(snaps, m, PREV, 'v1')
        pman = {x['path']: x for x in json.load(open(os.path.join(pv, 'manifest.json'), encoding='utf-8'))['files']}
        man_p = os.path.join(base, 'v1', 'manifest.json')
        man = json.load(open(man_p, encoding='utf-8'))
        todo = paths or [x['path'] for x in man['files'] if x['path'] in pman]
        for x in man['files']:
            if x['path'] in todo and x['path'] in pman:
                shutil.copyfile(os.path.join(pv, 'files', x['path']), os.path.join(base, 'v1', 'files', x['path']))
                for k in ('source', 'source_committed_at', 'fetched_at', 'as_of'):
                    x[k] = pman[x['path']].get(k)
        open(man_p, 'w', encoding='utf-8').write(json.dumps(man, ensure_ascii=False, indent=1, sort_keys=True))
        reseal(base)
    return f


def add_version(kind, invalidates, mutate):
    """v2 를 덧붙인다(v1 은 그대로 둔다). mutate(files_dir) 로 정정 내용을 넣는다."""
    def f(base):
        shutil.copytree(os.path.join(base, 'v1'), os.path.join(base, 'v2'))
        mutate(os.path.join(base, 'v2', 'files'))
        man_p = os.path.join(base, 'v2', 'manifest.json')
        man = json.load(open(man_p, encoding='utf-8'))
        man.update(version=2, kind=kind, invalidates=invalidates, note='시험: ' + kind)
        open(man_p, 'w', encoding='utf-8').write(json.dumps(man, ensure_ascii=False, indent=1, sort_keys=True))
        idx_p = os.path.join(base, 'index.json')
        idx = json.load(open(idx_p, encoding='utf-8'))
        idx['versions'].append({'v': 2, 'kind': kind, 'invalidates': invalidates, 'created_at': man['created_at'], 'manifest_sha256': '', 'note': man['note']})
        open(idx_p, 'w', encoding='utf-8').write(json.dumps(idx, ensure_ascii=False, indent=1))
        reseal(base, 2)
    return f


def corrupt(path):
    def f(base):
        p = os.path.join(base, 'v1', 'files', path)
        b = open(p, 'rb').read()
        open(p, 'wb').write(b.replace(b'2026-11-16', b'2026-11-16 ', 1) if b'2026-11-16' in b else b + b' ')
    return f


def xcheck_false(base):
    man_p = os.path.join(base, 'v1', 'manifest.json')
    man = json.load(open(man_p, encoding='utf-8'))
    for x in man['files']:
        if x['path'] == 'datadir/auctions.json':
            x['xcheck'] = dict(x.get('xcheck') or {}, equal=False)
    open(man_p, 'w', encoding='utf-8').write(json.dumps(man, ensure_ascii=False, indent=1, sort_keys=True))
    reseal(base)


# ── 글·자료 변조 ──────────────────────────────────────────────────────────

VAL = re.compile(r'\d[\d,]*\.\d+')


def paired_tamper(post, data_raw, heading):
    """heading 절의 표에서 숫자 하나를 골라 글과 자료(JSON 값)에서 똑같이 바꾼다 → (새 글, 새 자료, 설명).
    자료에는 반올림 전 값이 들어 있으므로, 글의 자릿수로 반올림해 같은 값을 모두 새 값으로 바꾼다."""
    text = post.decode('utf-8')
    h = re.search(r'<h[23][^>]*>[^<]*%s' % heading, text)
    end = text.index('</section>', h.end())
    doc = json.loads(data_raw)
    for t in re.finditer(r'<table\b.*?</table>', text[h.end():end], re.S):
        for tok in VAL.findall(re.sub(r'<[^>]+>', ' ', t.group(0))):
            plain = tok.replace(',', '')
            if sum(c.isdigit() for c in plain) < 4:
                continue
            nd = len(plain.split('.')[1])
            new_plain = plain[:-1] + str((int(plain[-1]) + 3) % 10)
            hits = [0]

            def walk(x):
                if isinstance(x, float) and not isinstance(x, bool) and ('%.*f' % (nd, x)) == plain:
                    hits[0] += 1
                    return float(new_plain)
                if isinstance(x, list):
                    return [walk(v) for v in x]
                if isinstance(x, dict):
                    return {k: walk(v) for k, v in x.items()}
                return x
            new_doc = walk(doc)
            if hits[0]:
                return (re.sub(r'(?<![\d.,])%s(?![\d])' % re.escape(tok), tok[:-1] + new_plain[-1], text).encode('utf-8'),
                        json.dumps(new_doc, ensure_ascii=False, indent=1).encode('utf-8'),
                        '%s → %s (자료 값 %d곳)' % (tok, tok[:-1] + new_plain[-1], hits[0]))
    raise ValueError('paired_tamper: no candidate in ' + heading)


def insert_before_section_end(post, heading, html):
    text = post.decode('utf-8')
    m = re.search(r'<h[23][^>]*>[^<]*%s' % heading, text)
    end = text.index('</section>', m.end())
    return (text[:end] + html + text[end:]).encode('utf-8')


AUCTION_SECTION = ('</section><section id="read-x"><h2>국채 입찰</h2><div data-auction-day="2026-11-16">'
                   '<p data-auction="nominal-30y">30년물 입찰은 응찰배율 2.36배, 딜러 비중 11.4%였다.</p></div>')
AUCTION_PROSE = '<p>재무부가 이날 판 30년물은 찾는 쪽이 적었다. 받아 간 물량에 견준 주문은 2.36배였고 금리는 5.441%에 정해졌다.</p>'


# ── 사례 ──────────────────────────────────────────────────────────────────

def build_cases(snaps):
    C = []

    def add(id_, m, what, expect, reason=None, **kw):
        C.append(dict(id=id_, market=m, what=what, expect=expect, reason=reason, **kw))

    # 정상 대조군 — 문지기가 「전부 보류」가 아님을 보인다
    add('P1', 'us', '정상 글·정상 자료', 'publish')
    add('P2', 'kr', '정상 글·정상 자료', 'publish')
    add('P3', 'us', '국채 입찰 자료 없음, 글에 입찰 절도 없음(선택 자료)', 'publish', gap='optional_input_absent:datadir/auctions.json', snap=drop('datadir/auctions.json'))
    add('P4', 'us', '유동성 자료 없음, 글에 유동성·수급 절도 없음(선택 자료)', 'publish', gap='optional_input_absent:datadir/liquidity/liquidity.json', snap=drop('datadir/liquidity/liquidity.json'))
    add('P5', 'kr', '특징주 묶음 자료 없음, 글에 묶음 표식도 없음(선택 자료)', 'publish', gap='optional_input_absent:datadir/kr_movers.json', snap=drop('datadir/kr_movers.json'))
    # 1. 입력 누락
    add('M1', 'us', '시세 자료(market_data) 없음', 'hold', 'required_input_missing:datadir/market_data.json', snap=drop('datadir/market_data.json'))
    add('M2', 'us', '경제지표 자료 없음 — 지금 운영 검사는 「일부만 검사」로 통과시킨다', 'hold', 'required_input_missing:datadir/econ_indicators.json', snap=drop('datadir/econ_indicators.json'))
    add('M3', 'us', '글에 국채 입찰 절을 실었는데 입찰 자료 없음', 'hold', 'required_input_missing:datadir/auctions.json', snap=drop('datadir/auctions.json'),
        post=lambda p: insert_before_section_end(p, '채권', AUCTION_SECTION))
    add('M4', 'us', '[자기 공격] 표식·절 제목·열쇠말 없이 문장으로만 입찰 결과를 쓰고 입찰 자료 없음', 'observe', snap=drop('datadir/auctions.json'),
        post=lambda p: insert_before_section_end(p, '채권', AUCTION_PROSE))
    add('M4b', 'us', '[자기 공격] 위와 같고, 문장 숫자 대조를 차단으로 켬', 'observe', snap=drop('datadir/auctions.json'),
        post=lambda p: insert_before_section_end(p, '채권', AUCTION_PROSE), prose_block=True)
    add('M4c', 'us', '[대조군] 같은 문장, 입찰 자료 있음, 문장 숫자 대조 차단', 'observe',
        post=lambda p: insert_before_section_end(p, '채권', AUCTION_PROSE), prose_block=True)
    add('M5', 'us', '장중 자료 없음, 글이 장중 흐름을 씀(어느 검사기도 이 자료를 안 본다)', 'hold', 'required_input_missing:datadir/intraday.json', snap=drop('datadir/intraday.json'))
    add('M6', 'kr', '시세 자료(kr_market_data) 없음', 'hold', 'required_input_missing:datadir/kr_market_data.json', snap=drop('datadir/kr_market_data.json'))
    add('M7', 'kr', '기술적 분석 자료 없음, 글에 기술적 분석 절 있음(어느 검사기도 이 자료를 안 본다)', 'hold', 'required_input_missing:datadir/kr_technical.json', snap=drop('datadir/kr_technical.json'))
    add('M8', 'kr', '판단 채점 자료(kr_stance_eval) 없음 — 지금 운영 검사는 그대로 통과시킨다', 'hold', 'required_input_missing:datadir/kr_stance_eval.json', snap=drop('datadir/kr_stance_eval.json'))
    add('M9', 'us', '그날 스냅샷이 아예 없음', 'hold', 'snapshot_missing', snap=lambda base: shutil.rmtree(base))
    # 검사 도구가 못 돎 — 글이 틀린 것과 다른 상태
    add('E1', 'us', '검사 프로그램 하나가 실행 오류로 죽음', 'hold', 'tool_error:check_fund', code='crash:check_fund.py')
    add('E2', 'kr', '검사 프로그램 하나가 없음', 'hold', 'tool_error:check_session', code='missing:check_session.py')
    add('E3', 'us', '[대조] 글 숫자가 틀림 — 도구 고장과 다른 이유 부호', 'hold', 'gate_failed:check_numbers', post='bump:주식')
    # 2. 입력 변조
    add('T1', 'us', '글의 숫자와 루틴 쪽 자료를 똑같이 고침 → 문지기는 보호된 자료로 검사', 'hold', 'gate_failed:check_numbers', tamper=('datadir/market_data.json', '원자재'))
    add('T1L', 'us', '[옛 방식 대조] 같은 조작, 문지기가 루틴 쪽 자료로 검사하면', 'publish', tamper=('datadir/market_data.json', '원자재'), legacy=True)
    add('T2', 'kr', '글의 숫자와 루틴 쪽 자료를 똑같이 고침 → 문지기는 보호된 자료로 검사', 'hold', 'gate_failed:check_numbers', tamper=('datadir/kr_market_data.json', '지수'))
    add('T2L', 'kr', '[옛 방식 대조] 같은 조작, 문지기가 루틴 쪽 자료로 검사하면', 'publish', tamper=('datadir/kr_market_data.json', '지수'), legacy=True)
    add('T3', 'us', '루틴이 정책에 없는 파일(시세 자료·검증 기록)을 「루틴 상태」로 끼워 냄 → 받지 않음', 'hold', 'gate_failed:check_numbers', tamper=('datadir/market_data.json', '원자재'), smuggle=True)
    add('X1', 'us', '스냅샷 파일이 목록의 해시와 다름(보관 중 변형)', 'hold', 'snapshot_file_hash_mismatch:datadir/market_data.json', snap=corrupt('datadir/market_data.json'))
    add('X2', 'us', '직접 받은 원천과 대역 자료가 어긋났다고 수집 기록에 적힘', 'hold', 'source_crosscheck_mismatch:datadir/auctions.json', snap=xcheck_false)
    # 3. 자료 시점
    add('S1', 'us', '스냅샷 전체가 전 거래일(11/13) 자료', 'hold', 'stale_input:datadir/market_data.json', snap=swap_from_prev(snaps, 'us', None))
    add('S2', 'us', '일정 자료 하나만 전 거래일 것(기준일이 섞임)', 'hold', 'stale_input:datadir/calendar.json', snap=swap_from_prev(snaps, 'us', ['datadir/calendar.json']))
    add('S3', 'us', '내용에 날짜가 없는 자료(경제지표)가 전 거래일에 받은 것', 'hold', 'stale_fetch:datadir/econ_indicators.json', snap=swap_from_prev(snaps, 'us', ['datadir/econ_indicators.json']))
    add('S4', 'kr', '스냅샷 전체가 전 거래일(11/13) 자료', 'hold', 'stale_input:datadir/kr_market_data.json', snap=swap_from_prev(snaps, 'kr', None))
    add('S5', 'kr', '장 구분 자료 하나만 전 거래일 것', 'hold', 'stale_input:datadir/kr_session.json', snap=swap_from_prev(snaps, 'kr', ['datadir/kr_session.json']))
    add('S6', 'kr', '내용에 날짜가 없는 자료(수급)가 전 거래일에 받은 것', 'hold', 'stale_fetch:datadir/kr_flows.json', snap=swap_from_prev(snaps, 'kr', ['datadir/kr_flows.json']))
    # 4. 재검증 — 이미 실린 글
    add('R1', 'us', '실린 글을 같은 자료로 다시 판정', 'publish', rejudge=True)
    add('R2', 'us', '실린 뒤 자료에 개정판(v2, 원천이 나중에 고침)이 덧붙음 — 승인 근거 v1 은 유효', 'publish', note='newer_snapshot_available:v2(revision)', rejudge=True, v2=('revision', []))
    add('R3', 'us', '실린 뒤 승인 근거였던 v1 이 잘못으로 판명(v2 정정판이 v1 을 무효로)', 'withdraw', 'gate_failed:check_numbers', note='approved_snapshot_invalidated:v1', rejudge=True, v2=('correction', [1]))
    add('R4', 'us', '개정판 v2 가 있을 때 새로 내는 글은 최신 판으로 본다', 'hold', 'gate_failed:check_numbers', v2=('revision', []))
    add('R5', 'us', '실린 글 재판정 때 검사 도구가 죽음 → 내리지 않고 표시만', 'keep_flagged', 'tool_error:check_fund', rejudge=True, code='crash:check_fund.py')
    add('R6', 'kr', '실린 뒤 승인 근거였던 v1 이 무효가 됨', 'withdraw', 'gate_failed:check_numbers', note='approved_snapshot_invalidated:v1', rejudge=True, v2=('correction', [1]))
    return C


def bump_table(post, heading):
    text = post.decode('utf-8')
    m = re.search(r'<h[23][^>]*>[^<]*%s' % heading, text)
    t = re.compile(r'<table\b.*?</table>', re.S).search(text, m.end())
    seg = re.sub(r'>[^<]+<', lambda x: VAL.sub(lambda v: v.group(0)[:-1] + str((int(v.group(0)[-1]) + 1) % 10), x.group(0)), t.group(0))
    return (text[:t.start()] + seg + text[t.end():]).encode('utf-8')


def code_variant(tmp, spec):
    kind, name = spec.split(':')
    root = os.path.join(tmp, 'code')
    shutil.copytree(J.CODE, root)
    p = os.path.join(root, 'scripts', name)
    if kind == 'crash':
        open(p, 'w').write('raise RuntimeError("simulated tool failure")\n')
    else:
        os.remove(p)
    return root


def v2_mutator(m):
    """자료의 숫자 하나를 바꾼 판 — 글이 표에 쓴 값이다."""
    path, heading = ('datadir/market_data.json', '원자재') if m == 'us' else ('datadir/kr_market_data.json', '지수')

    def mutate(files_dir, post):
        p = os.path.join(files_dir, path)
        _, new, desc = paired_tamper(post, open(p, 'rb').read(), heading)
        open(p, 'wb').write(new)
    return mutate


def run_case(arg):
    try:
        return _run_case(arg)
    except BaseException as exc:  # noqa: BLE001 — 사례 하나의 고장이 묶음 전체를 멈추면 안 된다
        import traceback
        return {'id': arg[0], 'market': '?', 'what': '사례 실행 오류', 'detail': traceback.format_exc()[-400:], 'expect': '?', 'expect_reason': '',
                'decision': 'case_error', 'reasons': [repr(exc)[:200]], 'gaps': [], 'notes': [], 'snapshot': None, 'post_sha256': None,
                'checker_tree_sha256': None, 'policy_sha256': None, 'gates': {}, 'hostile_executed': 0, 'ok': False}


def _run_case(arg):
    cid, snaps, out, snap_ref = arg
    c = next(x for x in build_cases(snaps) if x['id'] == cid)      # 사례에 함수가 들어 있어 번호만 넘겨받는다
    m = c['market']
    tmp = tempfile.mkdtemp(prefix='case-%s-' % c['id'])
    try:
        post0, sub = submission(m, out)
        post, detail = post0, ''
        if callable(c.get('post')):
            post = c['post'](post0)
        elif isinstance(c.get('post'), str):
            post = bump_table(post0, c['post'].split(':')[1])
        snap_edit = c.get('snap')
        sub = dict(sub, routine_state=dict(sub['routine_state']))
        if c.get('tamper'):
            path, heading = c['tamper']
            good = open(os.path.join(snaps, m, DATE, 'v1', 'files', path), 'rb').read()
            post, bad, detail = paired_tamper(post0, good, heading)
            if c.get('smuggle'):
                sub['routine_state'][path] = bad
                sub['routine_state']['verification/%s/%s.json' % (m, DATE)] = b'{"summary":{"publish_ok":true}}'
            if c.get('legacy'):                     # 옛 방식: 문지기가 루틴이 고친 자료를 그대로 믿는다
                def snap_edit(base, path=path, bad=bad):
                    open(os.path.join(base, 'v1', 'files', path), 'wb').write(bad)
                    reseal(base)
        if c.get('v2'):
            kind, inv = c['v2']
            mut = v2_mutator(m)
            snap_edit = add_version(kind, inv, lambda d: mut(d, post0))
        code = code_variant(tmp, c['code']) if c.get('code') else J.CODE
        prev, published = None, False
        if c.get('rejudge'):                         # 먼저 깨끗한 상태에서 승인받아 실린 것으로 만든다
            first = J.judge(m, DATE, post, sub, os.path.join(snaps), os.path.join(tmp, 'w0'), SUB[m]['cycle'], snap_ref=snap_ref)
            assert first['decision'] == 'publish', first['reasons']
            prev, published = J.ledger_entry(first), True
        root = view(snaps, tmp, m, snap_edit)
        if c.get('prose_block'):
            pol_dir = os.path.join(tmp, 'pol')
            shutil.copytree(os.path.join(HERE, 'inputs'), pol_dir)
        v = J.judge(m, DATE, post, sub, root, os.path.join(tmp, 'w1'), SUB[m]['cycle'], prev=prev, published=published, code=code,
                    snap_ref=snap_ref, extra_argv={'check_numbers': ['--prose', 'block']} if c.get('prose_block') else None)
        ok = True
        if c['expect'] != 'observe':
            ok = v['decision'] == c['expect']
            if c.get('reason'):
                ok = ok and any(r.startswith(c['reason']) for r in v['reasons'])
            if c.get('gap'):
                ok = ok and c['gap'] in v['gaps']
            if c.get('note'):
                ok = ok and c['note'] in v['notes']
        ok = ok and v['hostile_executed'] == 0
        return {'id': c['id'], 'market': m, 'what': c['what'], 'detail': detail, 'expect': c['expect'], 'expect_reason': c.get('reason') or c.get('gap') or c.get('note') or '',
                'decision': v['decision'], 'reasons': v['reasons'], 'gaps': v['gaps'], 'notes': v['notes'], 'snapshot': v['snapshot'],
                'post_sha256': v['post_sha256'], 'checker_tree_sha256': v['checker_tree_sha256'], 'policy_sha256': v['policy_sha256'],
                'gates': {g['name']: g['status'] for g in v['gates']}, 'hostile_executed': v['hostile_executed'], 'ok': ok}
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def survey(arg):
    """스냅샷 파일을 하나씩 빼고 판정 — 「32가지 중 21가지 통과」의 다시 재기."""
    m, path, snaps, out = arg
    tmp = tempfile.mkdtemp(prefix='sv-')
    try:
        post, sub = submission(m, out)
        v = J.judge(m, DATE, post, sub, view(snaps, tmp, m, drop(path)), os.path.join(tmp, 'w'), SUB[m]['cycle'])
        return {'market': m, 'removed': path, 'decision': v['decision'], 'reasons': v['reasons'],
                'gaps': [g for g in v['gaps'] if path in g], 'hostile_executed': v['hostile_executed']}
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--op-git', required=True)
    ap.add_argument('--snapshots', required=True)
    ap.add_argument('--out', required=True)
    ap.add_argument('--snap-ref')
    ap.add_argument('--jobs', type=int, default=4)
    ap.add_argument('--only')
    a = ap.parse_args()
    os.environ['DT_OP_GIT'] = os.path.abspath(a.op_git)
    snaps, out = os.path.abspath(a.snapshots), os.path.abspath(a.out)
    os.makedirs(out, exist_ok=True)
    for m in ('us', 'kr'):
        submission(m, out)                           # 한 번만 꺼내 둔다
    cases = [c for c in build_cases(snaps) if not a.only or c['id'] in a.only.split(',')]
    with Pool(a.jobs) as pool:
        rows = pool.map(run_case, [(c['id'], snaps, out, a.snap_ref) for c in cases])
        sv = []
        if not a.only:
            jobs = []
            for m in ('us', 'kr'):
                man = json.load(open(os.path.join(snaps, m, DATE, 'v1', 'manifest.json'), encoding='utf-8'))
                paths = [f['path'] for f in man['files']]
                if m == 'kr':                        # 지난 뉴스·텔레그램·주간 파일은 묶음마다 하나만
                    seen, keep = set(), []
                    for p in paths:
                        g = re.sub(r'(news|telegram|weekly|history)/[^/]+$', r'\1/', p)
                        if g not in seen or p.endswith(DATE + '.json'):
                            seen.add(g)
                            keep.append(p)
                    paths = keep
                jobs += [(m, p, snaps, out) for p in paths]
            sv = pool.map(survey, jobs)
    meta = {'gate_sha': os.environ.get('GITHUB_SHA'), 'run': os.environ.get('GITHUB_RUN_ID'),
            'run_url': '%s/%s/actions/runs/%s' % (os.environ.get('GITHUB_SERVER_URL'), os.environ.get('GITHUB_REPOSITORY'), os.environ.get('GITHUB_RUN_ID')) if os.environ.get('GITHUB_RUN_ID') else None,
            'data_repo_sha': a.snap_ref, 'python': sys.version.split()[0], 'submission_commits': {m: SUB[m]['commit'] for m in SUB},
            'planted_per_submission': len(PLANT)}
    json.dump({'meta': meta, 'cases': rows, 'survey': sv}, open(os.path.join(out, 'matrix.json'), 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
    lines = ['| 사례 | 시장 | 무엇을 | 기대 | 판정 | 이유 | 맞음 |', '|---|---|---|---|---|---|---|']
    for r in rows:
        why = '; '.join(r['reasons'][:3] + r['gaps'][:2] + r['notes'][:2])
        lines.append('| %s | %s | %s %s | %s %s | %s | %s | %s |' % (r['id'], r['market'], r['what'], ('(' + r['detail'] + ')') if r['detail'] else '',
                     r['expect'], r['expect_reason'], r['decision'], why, 'O' if r['ok'] else 'X'))
    if sv:
        lines += ['', '| 시장 | 뺀 파일 | 판정 | 이유 |', '|---|---|---|---|']
        for r in sv:
            lines.append('| %s | %s | %s | %s |' % (r['market'], r['removed'], r['decision'], '; '.join(r['reasons'][:2] + r['gaps'])))
        for m in ('us', 'kr'):
            x = [r for r in sv if r['market'] == m]
            lines.append('')
            lines.append('%s: 하나씩 뺀 %d가지 중 발행 %d · 보류 %d' % (m, len(x), sum(r['decision'] == 'publish' for r in x), sum(r['decision'] != 'publish' for r in x)))
    hostile = sum(r['hostile_executed'] for r in rows) + sum(r['hostile_executed'] for r in sv)
    bad = [r['id'] for r in rows if not r['ok']]
    lines += ['', 'cases %d · mismatched %d %s · hostile modules executed %d (planted %d per submission)' % (len(rows), len(bad), bad, hostile, len(PLANT))]
    open(os.path.join(out, 'matrix.md'), 'w', encoding='utf-8').write('\n'.join(lines) + '\n')
    print('\n'.join(lines))
    return 1 if bad or hostile else 0


if __name__ == '__main__':
    sys.exit(main())
