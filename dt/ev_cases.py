#!/usr/bin/env python3
"""판단 근거 확인 시험. 글·원장은 운영 저장소 발행 커밋(루틴이 낸 것의 대역), 종가 이력은 보호된 스냅샷에서만 읽는다.

  ev_cases.py --op-git <bare git> --snapshots <자료 저장소 snapshots/> --out <디렉터리>

근거 기록(ev_recipes.py)은 작성자가 낼 것을 대신 적은 것이다. 문지기는 그 기록을 믿지 않고 값을 다시 만든다.
"""
import argparse, copy, json, os, re, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import evidence as E      # noqa: E402
import ev_calc as C       # noqa: E402
import ev_recipes as RC   # noqa: E402

CODE = os.path.join(os.path.dirname(HERE), 'trusted_real')
POSTS = [('2026-11-03', '55edf2f15496643eefffd4573c5c17b159a96812', 'independent'), ('2026-11-04', '75ac3b2525fcb526bf9bf3e7f2e27d021f80593f', 'independent'),
         ('2026-11-05', '7d9fcdde1930de66f6a7b85a45bbd08f1588ca0c', 'independent'), ('2026-11-06', 'c93ea278aac51ce86be0d6d2a7599eeb65f93670', 'independent'),
         ('2026-11-09', '8bc6e2543befd876881f2294e00abd58ee89c82d', 'tuned'), ('2026-11-10', '4f51fd9bce246793d8e93688e73ebc6abb8dbce5', 'tuned'),
         ('2026-11-11', '68fdf456e1d9574d61f98d4f594f38dfa18bef98', 'tuned'), ('2026-11-12', '3ab3e3f617edc074d63ddc335722506fffd6a28b', 'tuned'),
         ('2026-11-13', '7e18f8bc2bdc20d736608414e29b2e07efc42833', 'tuned'), ('2026-11-16', '3378e19652bbd5fdfef8281d4b33ad7fe18a4cb5', 'tuned')]
NV = 'us-2026-11-09-nvidia-governance-discount-persist'
PW = 'us-2026-11-10-ai-power-softbank-order-risk'
NEW = 'us-2026-11-16-ai-hardware-derisking-vs-policy-reprice'


def git(op, *a):
    return subprocess.run(['git', '--git-dir', op, *a], capture_output=True, check=True).stdout


def history_path(snaps, date):
    """보호된 스냅샷의 최신 유효 판에서 종가 이력 파일 경로(없으면 None)."""
    base = os.path.join(snaps, 'us', date)
    try:
        idx = json.load(open(os.path.join(base, 'index.json'), encoding='utf-8'))
    except OSError:
        return None
    invalid = {i for x in idx['versions'] for i in x.get('invalidates') or []}
    for v in sorted((x['v'] for x in idx['versions'] if x['v'] not in invalid), reverse=True):
        p = os.path.join(base, 'v%d' % v, 'files', 'datadir', 'history', 'market.jsonl')
        if os.path.isfile(p):
            return p
    return None


def load(op, snaps, date, commit):
    post = git(op, 'cat-file', 'blob', '%s:posts/%s.html' % (commit, date)).decode('utf-8')
    ledger = [json.loads(l) for l in git(op, 'cat-file', 'blob', '%s:research/us/ledger.jsonl' % commit).decode('utf-8').splitlines() if l.strip()]
    ids = [h for h, _ in E.PARA.findall(post)]
    return post, ledger, ids, history_path(snaps, date)


def para_sub(post, hid, old, new):
    """그 가설 문단 안에서만 글자를 바꾼다."""
    def one(m):
        return m.group(0).replace(old, new) if m.group(1) == hid else m.group(0)
    out = E.PARA.sub(one, post)
    assert out != post, (hid, old)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--op-git', required=True)
    ap.add_argument('--snapshots', required=True)
    ap.add_argument('--out', required=True)
    a = ap.parse_args()
    op, snaps = os.path.abspath(a.op_git), os.path.abspath(a.snapshots)
    os.makedirs(a.out, exist_ok=True)
    date, commit = '2026-11-16', POSTS[-1][1]
    post, ledger, ids, hist = load(op, snaps, date, commit)
    rec0 = RC.record(date, ids)
    tmp = os.path.join(a.out, 'tmp')
    os.makedirs(tmp, exist_ok=True)

    def run(p=None, rec=None, h=None, led=None):
        return E.check(p if p is not None else post, rec0 if rec is None else rec, h or hist, ledger if led is None else led, CODE, date)

    def rec_edit(fn):
        r = copy.deepcopy(rec0)
        fn(r)
        return r

    def item(r, hid):
        return next(i for i in r['items'] if i['hypothesis'] == hid)

    cases = []

    def add(id_, what, expect, reason, res, scope='in'):
        ok = (not res['reasons']) if expect == 'pass' else any(x.startswith(reason) for x in res['reasons'])
        cases.append({'id': id_, 'what': what, 'expect': expect, 'expect_reason': reason or '', 'decision': 'pass' if not res['reasons'] else 'hold',
                      'reasons': res['reasons'][:6], 'tokens': res['tokens'], 'explained': res['explained'], 'scope': scope, 'ok': ok})

    add('EV0', '정상 글 + 정상 근거 기록', 'pass', None, run())
    add('EV1', '근거 기록을 아예 내지 않음', 'hold', 'evidence_missing', run(rec={}))
    add('EV2', '가설 하나의 근거 기록을 뺌', 'hold', 'evidence_missing:' + NV, run(rec=rec_edit(lambda r: r['items'].remove(item(r, NV)))))
    add('EV3', '근거 기록의 기준 산식을 바꿈(구간 20개 → 10개) — 글의 기준값과 세운 날의 기준값이 모두 안 맞게 된다', 'hold', 'criterion_changed_since_registration',
        run(rec=rec_edit(lambda r: item(r, NV)['criterion'].update(n=10))))
    add('EV4', '글의 계산값 하나를 고침(12.610% → 12.910%), 기록은 그대로', 'hold', 'unexplained_number:' + NV, run(p=para_sub(post, NV, '12.610%', '12.910%')))
    # 시작일을 유리한 날로 옮기고 글의 숫자도 그 계산에 맞게 고친다 — 계산은 맞지만 세운 날이 아니다
    H, dates = C.load(hist)
    alt = '2026-11-06'
    nv, sp = C.pct(H, 'memory.Nvidia', alt, date), C.pct(H, 'indices.S&P 500', alt, date)
    p5 = para_sub(post, NV, '12.610%', '%.3f%%' % abs(nv))
    p5 = para_sub(p5, NV, '1.766%', '%.3f%%' % abs(sp))
    p5 = para_sub(p5, NV, '-10.844%p', '%+.3f%%p' % (nv - sp))
    add('EV5', '시작일을 11/09 → 11/06 으로 옮기고 글의 숫자도 그 계산대로 고침(계산은 맞지만 가설을 세운 날이 아님)', 'hold', 'start_not_registered:' + NV,
        run(p=p5, rec=rec_edit(lambda r: item(r, NV).update(start=alt))))

    def e6(r):
        for x in item(r, PW)['extras']:
            if x['formula'] == 'chosen':
                x['value'] = 35
    add('EV6', '분석자가 고른 기준을 글과 기록에서 함께 바꿈(+25bp → +35bp)', 'hold', 'criterion_not_registered:' + PW, run(p=para_sub(post, PW, '+25bp', '+35bp'), rec=rec_edit(e6)))
    # 루틴이 자기 쪽 종가 이력을 고치고 글도 그에 맞춤 — 문지기는 보호된 이력만 읽는다
    rows = [json.loads(l) for l in open(hist, encoding='utf-8') if l.strip()]
    for r in rows:
        if r['report_date'] == date:                 # 끝 날짜의 종가만 고친다(기준값 계산 구간에는 안 들어가는 행)
            r['memory']['Nvidia'] = r['memory']['Nvidia'] * 0.95
    fake = os.path.join(tmp, 'routine_history.jsonl')
    open(fake, 'w', encoding='utf-8').write('\n'.join(json.dumps(r, ensure_ascii=False) for r in rows) + '\n')
    Hf, df = C.load(fake)
    nvf = C.pct(Hf, 'memory.Nvidia', '2026-11-09', date)
    p7 = para_sub(para_sub(post, NV, '12.610%', '%.3f%%' % abs(nvf)), NV, '-10.844%p', '%+.3f%%p' % (nvf - C.pct(Hf, 'indices.S&P 500', '2026-11-09', date)))
    add('EV7', '루틴이 자기 쪽 종가 이력을 고치고 글의 숫자도 그에 맞춤 → 문지기는 보호된 이력으로 다시 계산', 'hold', 'unexplained_number:' + NV, run(p=p7))
    add('EV7L', '[대조] 같은 조작, 문지기가 루틴 쪽 이력을 믿으면', 'pass', None, run(p=p7, h=fake))
    stale = os.path.join(tmp, 'stale_history.jsonl')
    open(stale, 'w', encoding='utf-8').write(''.join(l for l in open(hist, encoding='utf-8') if '"2026-11-16"' not in l[:40]))
    add('EV8', '보호된 종가 이력에 그날 행이 없음(수집이 멈춤)', 'hold', 'evidence_history_stale', run(h=stale))
    add('EV9', '근거 기록이 이력에 없는 계열을 가리킴', 'hold', 'evidence_input_missing:' + NV, run(rec=rec_edit(lambda r: item(r, NV).update(legs=['memory.NoSuch']))))
    add('EV10', '근거 기록이 어휘에 없는 산식을 씀', 'hold', 'evidence_input_missing:' + NV, run(rec=rec_edit(lambda r: item(r, NV).update(type='custom_formula'))))
    add('EV11', '판단 문단에 근거 없는 숫자를 덧붙임(「목표가는 200.50달러다」)', 'hold', 'unexplained_number:' + NV, run(p=para_sub(post, NV, '닫는다.', '닫는다. 목표가는 200.50달러다.')))
    add('EV12', '글에 없는 가설의 근거 기록을 끼워 냄', 'hold', 'evidence_for_absent_paragraph',
        run(rec=rec_edit(lambda r: r['items'].append(dict(copy.deepcopy(RC.R['us-2026-11-05-ai-chip-crash-degross-vs-rerating']), hypothesis='us-2026-11-05-ai-chip-crash-degross-vs-rerating', end=date)))))
    add('EV13', '가설을 세운 날의 원장 항목이 없음(등록되지 않은 가설)', 'hold', 'hypothesis_not_registered:' + NV, run(led=[r for r in ledger if r.get('id') != NV]))
    # 보증 범위 밖 — 통과한다는 것을 숨기지 않고 적는다
    add('X1', '[보증 범위 밖] 판단 문단에 숫자 없는 단정을 덧붙임(「이 판단은 이미 사실로 확인됐다」)', 'pass', None, run(p=para_sub(post, NV, '닫는다.', '닫는다. 이 판단은 이미 사실로 확인됐다.')), scope='out')
    add('X2', '[보증 범위 밖] 방향어를 뒤집음(「12.610% 내리고」 → 「12.610% 오르고」)', 'pass', None, run(p=para_sub(post, NV, '12.610% 내리고', '12.610% 오르고')), scope='out')
    add('X3', '[보증 범위 밖] 판단 문단 밖(전략 코멘트)의 같은 기준값을 고침(3.03%p → 3.30%p)', 'pass', None, run(p=post.replace('3.03%p', '3.30%p', 1) if post.index('3.03%p') < post.index('data-hypothesis') else post), scope='out')
    add('X4', '[보증 범위 밖] 기준 자체가 부적절함(구간 20개가 아니라 5개로 세웠어도, 세운 날 원장에 그렇게 적혀 있으면 통과한다)', 'pass', None, run(), scope='out')

    real = []
    for d, c, group in POSTS:
        try:
            p, led, hid, hp = load(op, snaps, d, c)
        except subprocess.CalledProcessError:
            continue
        if hp is None:
            real.append({'date': d, 'group': group, 'decision': 'n/a', 'why': '그 날짜의 보호된 종가 이력 없음'})
            continue
        r = E.check(p, RC.record(d, hid), hp, led, CODE, d)
        kinds = {}
        for x in r['paragraphs']:
            for k, n in x['kinds'].items():
                kinds[k] = kinds.get(k, 0) + n
        why = {}
        for x in r['reasons']:
            why[x.split(':')[0].split('(')[0]] = why.get(x.split(':')[0].split('(')[0], 0) + 1
        real.append({'date': d, 'group': group, 'paragraphs': len(hid), 'with_record': sum(1 for h in hid if h in RC.R), 'tokens': r['tokens'], 'explained': r['explained'],
                     'decision': 'pass' if not r['reasons'] else 'hold', 'why': why, 'kinds': kinds, 'human_judgment': len(r['human_judgment']), 'reasons': r['reasons']})

    meta = {'gate_sha': os.environ.get('GITHUB_SHA'), 'run': os.environ.get('GITHUB_RUN_ID'), 'python': sys.version.split()[0]}
    json.dump({'meta': meta, 'cases': cases, 'real_posts': real}, open(os.path.join(a.out, 'evidence_matrix.json'), 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
    L = ['| 사례 | 무엇을 | 기대 | 판정 | 이유 | 맞음 |', '|---|---|---|---|---|---|']
    for c in cases:
        L.append('| %s | %s | %s %s | %s | %s | %s |' % (c['id'], c['what'], c['expect'], c['expect_reason'], c['decision'], '; '.join(c['reasons'][:2]), 'O' if c['ok'] else 'X'))
    L += ['', '실제 글의 판단 문단(근거 기록은 세운 날 원장 문구로 적은 것)', '', '| 날짜 | 구분 | 문단(기록 있음) | 숫자 | 설명됨 | 판정 | 이유 종류 |', '|---|---|---|---|---|---|---|']
    for r in real:
        if r['decision'] == 'n/a':
            L.append('| %s | %s | - | - | - | n/a | %s |' % (r['date'], r['group'], r['why']))
        else:
            L.append('| %s | %s | %d(%d) | %d | %d | %s | %s |' % (r['date'], r['group'], r['paragraphs'], r['with_record'], r['tokens'], r['explained'], r['decision'], r['why']))
    bad = [c['id'] for c in cases if not c['ok']]
    L += ['', 'evidence cases %d · as expected %d · unexpected %d %s · out-of-scope cases that pass (by design, not guaranteed) %d' % (
        len(cases), sum(c['ok'] for c in cases), len(bad), bad, sum(1 for c in cases if c['scope'] == 'out'))]
    for g in ('tuned', 'independent'):
        x = [r for r in real if r['group'] == g and r['decision'] != 'n/a']
        L.append('%s posts %d · pass %d · numbers %d · explained %d' % (g, len(x), sum(r['decision'] == 'pass' for r in x), sum(r['tokens'] for r in x), sum(r['explained'] for r in x)))
    open(os.path.join(a.out, 'evidence_matrix.md'), 'w', encoding='utf-8').write('\n'.join(L) + '\n')
    print('\n'.join(L))
    return 1 if bad else 0


if __name__ == '__main__':
    sys.exit(main())
