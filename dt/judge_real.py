#!/usr/bin/env python3
"""실제 일간 글의 판정 (시험). 원칙:

- 검사 자료는 **보호된 스냅샷**에서만 온다. 루틴이 낸 것에서는 글 바이트와 「루틴 상태」 파일만 받는다
  (루틴의 검증 기록·입력 목록·자료는 읽지 않는다).
- 필수 입력은 **글 바이트**가 정한다: 늘 필수 / 글이 그 내용을 실었을 때만 필수 / 없어도 됨(기록만).
- 검사 코드는 문지기의 고정 사본에서만 실행한다. 루틴이 낸 파일은 실행하지 않는다.
- 통과가 아닌 모든 상태에 이유 부호를 남긴다. 검사 도구가 못 돈 것(tool_error)과 글이 틀린 것(gate_failed)은 다른 상태다.
- 이미 실린 글도 부를 때마다 다시 판정한다. 승인 근거였던 스냅샷 판이 무효가 되면 최신 판으로 다시 본다.
"""
import hashlib, html, importlib.util, json, os, re, shutil, subprocess, sys, unicodedata

HERE = os.path.dirname(os.path.abspath(__file__))
CODE = os.path.join(os.path.dirname(HERE), 'trusted_real')
TAG = re.compile(r'<[^>]+>')
HEAD = re.compile(r'<h[1-4]\b[^>]*>(.*?)</h[1-4]\s*>', re.S | re.I)


def sha(b):
    return hashlib.sha256(b).hexdigest()


def tree_sha(root):
    h = hashlib.sha256()
    for d, dirs, names in os.walk(root):
        dirs.sort()
        for n in sorted(names):
            if n.endswith('.pyc'):
                continue
            p = os.path.join(d, n)
            h.update(os.path.relpath(p, root).encode() + b'\0' + sha(open(p, 'rb').read()).encode() + b'\n')
    return h.hexdigest()


def load_record(code):
    sys.path.insert(0, os.path.join(code, 'scripts'))
    spec = importlib.util.spec_from_file_location('pinned_record', os.path.join(code, 'scripts', 'verification', 'record.py'))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ── 스냅샷 ────────────────────────────────────────────────────────────────

def pick_version(snap_root, market, date, prev):
    """(판 번호, 색인, 이유들). prev = 이 글을 전에 승인했을 때의 기록(없으면 None)."""
    base = os.path.join(snap_root, market, date)
    try:
        idx = json.load(open(os.path.join(base, 'index.json'), encoding='utf-8'))
        vs = idx['versions']
        assert vs and all(isinstance(x['v'], int) for x in vs)
    except Exception:
        return None, None, ['snapshot_missing']
    invalid = {i for x in vs for i in x.get('invalidates') or []}
    valid = [x['v'] for x in vs if x['v'] not in invalid]
    if not valid:
        return None, idx, ['snapshot_all_invalidated']
    latest = max(valid)
    notes = []
    if prev and prev.get('snapshot_version') in valid:
        basis = prev['snapshot_version']          # 승인 근거 판이 살아 있다 — 그 판 기준으로 다시 본다
        if latest != basis:
            notes.append('newer_snapshot_available:v%d(%s)' % (latest, next(x['kind'] for x in vs if x['v'] == latest)))
    else:
        basis = latest
        if prev and prev.get('snapshot_version') in invalid:
            notes.append('approved_snapshot_invalidated:v%d' % prev['snapshot_version'])
    return basis, idx, notes


def load_snapshot(snap_root, market, date, v, idx):
    """(manifest, 파일 바이트 {경로: bytes}, 오류들). 해시가 색인·목록과 어긋나면 오류."""
    vdir = os.path.join(snap_root, market, date, 'v%d' % v)
    errs, files = [], {}
    try:
        raw = open(os.path.join(vdir, 'manifest.json'), 'rb').read()
        man = json.loads(raw)
    except Exception:
        return None, {}, ['snapshot_manifest_unreadable']
    want = next((x.get('manifest_sha256') for x in idx['versions'] if x['v'] == v), None)
    if want != sha(raw):
        errs.append('snapshot_manifest_hash_mismatch')
    for f in man.get('files') or []:
        p = os.path.normpath(os.path.join(vdir, 'files', f['path']))
        if not p.startswith(os.path.join(vdir, 'files') + os.sep) or not os.path.isfile(p) or os.path.islink(p):
            errs.append('snapshot_file_missing:' + f['path'])
            continue
        b = open(p, 'rb').read()
        if sha(b) != f.get('sha256'):
            errs.append('snapshot_file_hash_mismatch:' + f['path'])
            continue
        if not f.get('source') or not f.get('fetched_at'):
            errs.append('snapshot_provenance_missing:' + f['path'])
        if isinstance(f.get('xcheck'), dict) and f['xcheck'].get('equal') is False:
            errs.append('source_crosscheck_mismatch:' + f['path'])
        files[f['path']] = b
    return man, files, errs


# ── 필수 입력·시점 ────────────────────────────────────────────────────────

def plain(s):
    """독자가 보는 글자로 편다 — 문자 참조를 풀고, 호환 문자를 합치고, 폭 없는 문자를 빼고, 공백을 하나로.
    안 하면 문자 참조로 적은 글자나 폭 없는 문자를 끼운 제목이 조건을 피한다."""
    s = unicodedata.normalize('NFKC', html.unescape(s))
    s = ''.join(c for c in s if unicodedata.category(c) not in ('Cf', 'Cc') or c in '\n\t')
    return re.sub(r'\s+', ' ', s)


def triggers(post_text, need):
    """글 바이트가 이 자료를 요구하는가 → 걸린 조건 이름들."""
    hit = []
    visible = plain(TAG.sub(' ', post_text))
    heads = ' | '.join(plain(TAG.sub('', h)) for h in HEAD.findall(post_text))
    if need.get('marker') and re.search('<[^>]*?\\s' + need['marker'], post_text, re.I):
        hit.append('marker')
    if need.get('heading') and re.search(need['heading'], heads):
        hit.append('heading')
    if need.get('text') and re.search(need['text'], visible, re.I):
        hit.append('text')
    return hit


def content_date(path, raw, where=True):
    """내용 속 기준일. where 가 문자열이면 그 점 경로(예: 「코스피.as_of」)에서, True 면 맨 위의 report_date·date 에서."""
    if not path.endswith('.json'):
        return None
    try:
        doc = json.loads(raw)
    except ValueError:
        return 'unreadable'
    if isinstance(where, str):
        for k in where.split('.'):
            doc = doc.get(k) if isinstance(doc, dict) else None
        return doc if isinstance(doc, str) else None
    if isinstance(doc, dict):
        for k in ('report_date', 'date'):
            if isinstance(doc.get(k), str):
                return doc[k]
    return None


def section_text(post_text, heading):
    """heading 에 맞는 제목이 든 절의 보이는 글자(없으면 빈 문자열)."""
    for m in re.finditer(r'<section\b[^>]*>.*?</section\s*>', post_text, re.S | re.I):
        if any(re.search(heading, plain(TAG.sub('', h))) for h in HEAD.findall(m.group(0))):
            return plain(TAG.sub(' ', m.group(0)))
    return ''


def disclosed(post_text, spec, d):
    """낡은 기준일 d(YYYY-MM-DD)를 글이 그 절에서 밝혔는가 — 「11월 13일」 꼴로 찾는다."""
    need = spec.get('need')
    if not (spec.get('stale_ok_if_disclosed') and isinstance(need, dict) and need.get('heading')):
        return False
    m = re.fullmatch(r'\d{4}-(\d{2})-(\d{2})', d or '')
    if not m:
        return False
    return bool(re.search(r'(?<!\d)%d월 ?%d일' % (int(m.group(1)), int(m.group(2))), section_text(post_text, need['heading'])))


def previous_files(snap_root, market, date):
    """(앞 날짜, {경로: sha256}) — 이 시장에서 date 보다 앞선 가장 가까운 스냅샷의 최신 유효 판."""
    base = os.path.join(snap_root, market)
    try:
        days = sorted(d for d in os.listdir(base) if re.fullmatch(r'\d{4}-\d{2}-\d{2}', d) and d < date)
    except OSError:
        return None, {}
    for d in reversed(days):
        v, idx, _ = pick_version(snap_root, market, d, None)
        if v is None:
            continue
        try:
            man = json.load(open(os.path.join(base, d, 'v%d' % v, 'manifest.json'), encoding='utf-8'))
            return d, {f['path']: f['sha256'] for f in man['files']}
        except Exception:
            continue
    return None, {}


def check_inputs(policy, post_text, man, files, date, prev=(None, {})):
    reasons, gaps, used = [], [], []
    meta = {f['path']: f for f in man['files']}
    for spec in policy['files']:
        path, need = spec['path'], spec.get('need', 'none')
        required = need == 'always'
        why = ['always'] if required else []
        if isinstance(need, dict):
            why = triggers(post_text, need)
            required = bool(why)
        if path not in files:
            if required:
                reasons.append('required_input_missing:%s(%s)' % (path, '+'.join(why)))
            else:
                gaps.append('optional_input_absent:' + path)
            continue
        if not required:
            if isinstance(need, dict):
                for toks, sent in unmarked_use(post_text, path, files, need.get('claim') or need.get('related'))[:2]:
                    # 그 자료의 절·표식 없이 값만 문장에 썼다 — 그 자료를 보는 검사가 이 문장을 읽지 않는다
                    reasons.append('unmarked_claim:%s(%s)' % (path, '·'.join(toks)))
            continue                                  # 글이 쓰지 않는 자료의 시점은 따지지 않는다
        used.append(path)
        if spec.get('asof'):
            d = content_date(path, files[path], spec['asof'])   # 수집 기록이 아니라 내용에서 문지기가 직접 읽는다
            if d != date:
                if disclosed(post_text, spec, d):
                    gaps.append('stale_but_disclosed:%s(as_of=%s)' % (path, d))   # 낡았지만 글이 그 기준일을 밝혔다
                else:
                    reasons.append('stale_input:%s(as_of=%s)' % (path, d))
        elif spec.get('fresh') == 'fetched':
            m = meta[path]
            t = (m.get('source_committed_at') or m.get('fetched_at') or '')[:10]
            if not t or t < date:
                reasons.append('stale_fetch:%s(collected=%s)' % (path, t or 'unknown'))
            elif spec.get('daily') and prev[1].get(path) == sha(files[path]):
                # 받은 시각은 오늘이어도 내용이 앞 거래일과 한 바이트도 다르지 않다 — 시각이 아니라 내용으로 본다
                reasons.append('stale_content:%s(same_bytes_as=%s)' % (path, prev[0]))
    return reasons, gaps, used


NUMTOK = re.compile(r'(?<![\d.,])(\d{1,3}(?:,\d{3})+(?:\.\d+)?|\d+\.\d+|\d{3,})(?![\d])')


def _leaves(x):
    if isinstance(x, bool):
        return
    if isinstance(x, (int, float)):
        yield x
    elif isinstance(x, list):
        for v in x:
            yield from _leaves(v)
    elif isinstance(x, dict):
        for v in x.values():
            yield from _leaves(v)


def _values(raw):
    try:
        return list(_leaves(json.loads(raw)))
    except ValueError:
        return []


def unmarked_use(post_text, path, files, related):
    """조건부 자료가 **있는데** 글이 그 절·표식 없이 그 자료의 값을 문단에 썼는가 → 걸린 문단들.
    한 문단(<p>·<li>) 안에 그 자료와 닿는 낱말이 있고, 그 자료의 값(유효 숫자 셋 이상)이 둘 이상 나올 때만 건다.
    좁은 규칙이다: 숫자 없이 풀어 쓴 주장, 숫자 하나짜리 주장, 닿는 낱말을 피한 주장은 못 잡는다."""
    if not related or not path.endswith('.json') or path not in files:
        return []
    mine = _values(files[path])
    if not mine:
        return []
    body = re.sub(r'<details\b.*?</details\s*>|<table\b.*?</table\s*>|<script\b.*?</script\s*>|<style\b.*?</style\s*>', ' ', post_text, flags=re.S | re.I)
    hits = []
    for m in re.finditer(r'<(p|li)\b[^>]*>(.*?)</\1\s*>', body, re.S | re.I):
        para = plain(TAG.sub(' ', m.group(2)))
        if not re.search(related, para, re.I):
            continue
        got = set()
        for t in NUMTOK.finditer(para):
            tok = t.group(1).replace(',', '')
            if sum(c.isdigit() for c in tok) < 3:
                continue
            dec = len(tok.split('.')[1]) if '.' in tok else 0
            if any('%.*f' % (dec, abs(v)) == tok for v in mine):
                got.add(tok)
        if len(got) >= 2:
            hits.append((sorted(got), para[:120]))
    return hits


def plain_keep_lines(s):
    s = unicodedata.normalize('NFKC', html.unescape(s))
    s = ''.join(c for c in s if unicodedata.category(c) not in ('Cf', 'Cc') or c in '\n\t')
    return re.sub(r'[ \t]+', ' ', s)


# ── 검사 실행 ─────────────────────────────────────────────────────────────

TOOL = ('검사기가 위반이 아니라 실행 오류로 끝났다', '알 수 없는 종료 코드', '결과를 읽지 못했다', '결과 형식이 약속과 다르다',
        '종료 코드와 결과가 어긋난다', '적용일을 읽지 못했다', '검사 프로그램이 없다', '시간 초과', '실행하지 못했다')


def run_checks(code, market, post, date, cycle, work, policy, post_text, timeout=180):
    R = load_record(code)
    cfg = json.load(open(os.path.join(code, 'config', 'prepub_gates.json'), encoding='utf-8'))
    ctx = {'html': post, 'datadir': os.path.join(work, 'datadir'), 'repo': os.path.join(work, 'src'), 'date': date, 'cycle': cycle}
    if market == 'us':
        ctx['tg'] = os.path.join(work, 'datadir', 'telegram.json')
    else:
        ctx['tg'] = os.path.join(work, 'tg', 'kr_telegram.json')
        ctx['stance_next'] = os.path.join(work, 'stance_next', 'kr_stance_next.json')
    env = {'PATH': '/usr/bin:/bin', 'HOME': os.path.join(work, 'home'), 'MARK': os.path.join(work, 'pwned')}
    os.makedirs(env['HOME'], exist_ok=True)
    foreign = os.path.join(work, 'foreign-code.txt')       # 믿는 곳 밖의 코드가 실행되면 실행 틀이 여기 적는다
    launcher = os.path.join(HERE, 'launch.py')
    out, reasons, gaps = [], [], []
    for spec in cfg['markets'][market]['gates']:
        res = R._base(spec)
        if spec.get('builtin') == 'unconfirmed':
            n = post_text.count('확인필요')
            res.update(exit=0 if n == 0 else 1, status='pass' if n == 0 else 'fail')
        elif spec.get('builtin'):
            res['reason'] = '모르는 내장 검사'
        else:
            eff = R._effective(spec)
            argv, missing = R._argv(spec, ctx)
            argv += policy.get('extra_argv', {}).get(spec['name'], [])
            script = os.path.join(code, argv[0])
            if eff is False:
                res['reason'] = '적용일을 읽지 못했다'
            elif eff and date < eff:
                res.update(status='not_run', reason='적용일 전')
            elif missing:
                res['reason'] = '필수 입력 누락: ' + ', '.join(missing)
            elif not os.path.isfile(script):
                res['reason'] = '검사 프로그램이 없다'
            else:
                try:
                    # -I: 환경 변수·사용자 폴더·현재 폴더를 import 경로에서 뺀다. -S: site(시스템·사용자 sitecustomize)를 불러오지 않는다.
                    # 실행 틀이 첫 경로를 검사기 폴더로 직접 잡으므로 -I 로도 검사기의 import 는 그대로 된다.
                    p = subprocess.run([sys.executable, '-I', '-S', launcher, code, foreign, script, *argv[1:]], capture_output=True, text=True,
                                       cwd=ctx['repo'], env=env, timeout=timeout)
                    res['exit'] = p.returncode
                    res['status'] = R._classify(spec, p.returncode, p.stdout, p.stderr, ctx, res)
                except subprocess.TimeoutExpired:
                    res.update(timed_out=True, reason='시간 초과')
                except OSError:
                    res['reason'] = '실행하지 못했다'
        st, name = res['status'], res['name']
        out.append({'name': name, 'required': res['required'], 'status': st, 'exit': res['exit'], 'reason': res.get('reason') or '',
                    'first': ((res.get('items') or [''])[0])[:160]})
        if st == 'warn':
            gaps.append('check_warned:' + name)
        if not res['required'] or st in ('pass', 'warn'):
            continue
        if st == 'fail':
            reasons.append('gate_failed:' + name)
        elif st == 'not_run' and (res.get('reason') or '').startswith('적용일'):
            # 검사기의 적용일(고정 사본 안의 상수) 전 글이다 — 건너뛴 것이 아니라 아직 적용 대상이 아니다
            gaps.append('check_not_yet_effective:%s' % name)
        elif st in ('not_run', 'partial'):
            ok = policy.get('skip_ok', {}).get(name)
            if ok and not re.search('<[^>]*?\\s' + ok['unless_marker'], post_text, re.I):
                gaps.append('check_not_applicable:%s' % name)
            else:
                reasons.append('check_skipped:%s(%s)' % (name, st))
        elif any(res.get('reason', '').startswith(t) for t in TOOL) or res.get('timed_out') or res['exit'] is None:
            reasons.append('tool_error:' + name)
        else:
            reasons.append('check_input_unreadable:' + name)
    executed = sorted(set(open(env['MARK']).read().split())) if os.path.exists(env['MARK']) else []
    if os.path.exists(foreign):
        executed += sorted(set(open(foreign, encoding='utf-8').read().split('\n')) - {''})
    if executed:
        reasons.append('untrusted_code_executed:%d' % len(executed))
    return out, reasons, gaps, executed


INFRA = ('tool_error', 'snapshot_missing', 'source_crosscheck_mismatch', 'snapshot_all_invalidated', 'snapshot_manifest_unreadable', 'snapshot_manifest_hash_mismatch',
         'snapshot_file_missing', 'snapshot_file_hash_mismatch', 'snapshot_provenance_missing')


# ── 판정 ──────────────────────────────────────────────────────────────────

def judge(market, date, post_bytes, submit, snap_root, work, cycle, prev=None, published=False, code=CODE, snap_ref=None, extra_argv=None, absent_conditional=None, reviews=None):
    """submit: 루틴이 낸 것 가운데 받는 것만 {'routine_state': {경로: bytes}, 'src': 디렉터리(연구 원장·이전 글)}.
    prev: 전에 이 글을 승인한 기록. published: 지금 이 바이트가 실려 있는가."""
    policy = json.load(open(os.path.join(HERE, 'inputs', market + '.json'), encoding='utf-8'))
    if extra_argv:
        policy['extra_argv'] = extra_argv
    if absent_conditional:
        policy['absent_conditional'] = absent_conditional
    v = {'market': market, 'date': date, 'post_sha256': sha(post_bytes), 'checker_tree_sha256': tree_sha(code),
         'policy_sha256': sha(open(os.path.join(HERE, 'inputs', market + '.json'), 'rb').read()),
         'reasons': [], 'gaps': [], 'notes': [], 'gates': [], 'snapshot': None,
         'self_consistency_only': policy.get('self_consistency_only', []), 'hostile_executed': 0, 'foreign_code': []}
    try:
        post_text = post_bytes.decode('utf-8')
    except UnicodeDecodeError:
        v['reasons'].append('post_not_utf8')
        post_text = None
    if prev and prev.get('post_sha256') != v['post_sha256']:
        prev = None                                           # 다른 바이트는 새 글이다
    ver, idx, notes = pick_version(snap_root, market, date, prev)
    v['notes'] += [n for n in notes if n not in ('snapshot_missing', 'snapshot_all_invalidated')]
    v['reasons'] += [n for n in notes if n in ('snapshot_missing', 'snapshot_all_invalidated')]
    if ver is not None and post_text is not None:
        man, files, errs = load_snapshot(snap_root, market, date, ver, idx)
        v['reasons'] += errs
        if errs:
            man = None                     # 스냅샷을 믿을 수 없으면 그 자료로 검사하지 않는다 — 뒤따르는 누락·실패는 원인이 아니다
        if man is not None:
            v['snapshot'] = {'version': ver, 'kind': man.get('kind'), 'ref': snap_ref,
                             'manifest_sha256': next(x['manifest_sha256'] for x in idx['versions'] if x['v'] == ver)}
            r, g, used = check_inputs(policy, post_text, man, files, date, previous_files(snap_root, market, date))
            v['reasons'] += r
            v['gaps'] += g
            v['required_inputs'] = used
            meta = {f['path']: f for f in man['files']}
            v['inputs'] = []
            for path in used:
                m = meta.get(path, {})
                sv = (m.get('source_verified') or {}).get('status') or ('matched' if (m.get('xcheck') or {}).get('equal') is True else 'not_verified')
                v['inputs'].append({'path': path, 'sha256': m.get('sha256'), 'as_of': content_date(path, files[path]), 'fetched_at': m.get('fetched_at'),
                                    'source_changed_at': m.get('source_committed_at'), 'source': m.get('source'), 'source_verified': sv})
            v['source_unverified_inputs'] = sum(1 for i in v['inputs'] if i['source_verified'] != 'matched')
            if os.path.exists(work):
                shutil.rmtree(work)
            for path, b in files.items():                      # 검사 자료는 스냅샷에서만
                dst = os.path.join(work, path)
                os.makedirs(os.path.dirname(dst), exist_ok=True)
                open(dst, 'wb').write(b)
            for path, b in (submit.get('routine_state') or {}).items():
                if path not in policy['routine_state']:
                    continue                                   # 정책에 없는 파일은 받지 않는다
                dst = os.path.join(work, path)
                os.makedirs(os.path.dirname(dst), exist_ok=True)
                open(dst, 'wb').write(b)
            os.makedirs(os.path.join(work, 'datadir'), exist_ok=True)
            src = os.path.join(work, 'src')
            if submit.get('src'):
                shutil.copytree(submit['src'], src, symlinks=True)
            else:
                os.makedirs(src)
            post = os.path.join(work, 'post', os.path.basename(policy['post'].format(date=date)))
            os.makedirs(os.path.dirname(post))
            open(post, 'wb').write(post_bytes)
            gates, r, g, executed = run_checks(code, market, post, date, cycle, work, policy, post_text)
            v['gates'], v['hostile_executed'], v['foreign_code'] = gates, len(executed), executed[:20]
            v['reasons'] += r
            v['gaps'] += g
    cond = {f['path'] for f in policy['files'] if isinstance(f.get('need'), dict)}
    absent_cond = [g.split(':', 1)[1] for g in v['gaps'] if g.startswith('optional_input_absent:') and g.split(':', 1)[1] in cond]
    pending = []
    if policy.get('absent_conditional') == 'review':
        # 조건부 자료가 빠졌고 글의 표식·제목·열쇠말에도 안 걸렸다. 글이 그 내용을 문장으로만 썼는지는 기계가 가릴 수 없다.
        # 사람은 「이 글에 그 자료가 필요한가」만 답한다: 필요 없음 → 발행 / 필요함 → 근거를 구하거나 그 주장을 빼고 다시 낸다.
        # 「자료 없이 그대로 발행」이라는 답은 없다. 답은 글 해시에 묶인다(글이 바뀌면 다시 묻는다).
        mine = (reviews or {}).get(v['post_sha256'], {})
        related = {f['path']: f['need'].get('related') for f in policy['files'] if isinstance(f.get('need'), dict)}
        visible = plain(TAG.sub(' ', post_text or ''))
        for path in absent_cond:
            d = mine.get(path)
            # 「닿는 낱말이 글에 없으면 자동 통과」는 두지 않는다 — 낱말을 피한 주장이 그대로 나가고(시험 O2),
            # 실제 글 12편에서 그 경로는 한 번도 쓰이지 않았다. 조건부 자료가 빠진 날은 늘 사람이 본다.
            if d == 'not_needed':
                v['notes'].append('human_confirmed_not_needed:' + path)
            elif d == 'needed':
                v['reasons'].append('claim_without_evidence:' + path)
            else:
                pending.append(path)
    ok = not v['reasons']
    if pending:
        v['notes'].append('conditional_evidence_absent:' + ','.join(pending))
    if ok and pending and not published:
        v['decision'] = 'needs_review'
        return v
    infra = all(r.split(':')[0] in INFRA for r in v['reasons'])
    # 실려 있는 글: 내용이 떨어지면 내리고, 검사 도구·스냅샷 쪽 고장뿐이면 내리지 않고 표시만 한다(새 글은 어느 쪽이든 보류)
    v['decision'] = 'publish' if ok else (('keep_flagged' if infra else 'withdraw') if published else 'hold')
    return v


def ledger_entry(v):
    return {'post_sha256': v['post_sha256'], 'snapshot_version': v['snapshot']['version'],
            'manifest_sha256': v['snapshot']['manifest_sha256'], 'checker_tree_sha256': v['checker_tree_sha256']}
