#!/usr/bin/env python3
"""실험용 문지기 v2. 원본(src)은 자료로만 읽는다. 내보낼 트리는 **허용 목록** 으로만 만든다:
경로가 알려진 분류에 맞고 그 분류의 규칙을 통과한 파일만 싣는다. 나머지는 싣지 않는다."""
import hashlib, json, os, re, shutil, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__))


def sha(path):
    with open(path, 'rb') as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def text_of(path):
    raw = open(path, encoding='utf-8', errors='replace').read()
    return ' '.join(re.sub(r'<[^>]+>', ' ', raw).split())


def shingles(text, n=5):
    w = text.split()
    return {' '.join(w[i:i + n]) for i in range(max(0, len(w) - n + 1))}


def rerun(rel, src, policy):
    for name in policy['required']:
        try:
            data_dir = os.path.join(HERE, 'trusted_data') if policy.get('data_source') == 'locked' else os.path.join(src, 'data')
            r = subprocess.run([sys.executable, '-I', '-S', os.path.join(HERE, 'trusted', name + '.py'),
                                os.path.join(src, rel), data_dir], capture_output=True, text=True, timeout=60, cwd=HERE)
        except Exception:  # noqa: BLE001
            return 'tool_error:' + name
        if r.returncode == 1 and r.stdout.startswith('fail'):
            return 'gate_failed:' + name
        if r.returncode == 3:
            return 'input_missing:' + name
        if r.returncode != 0:
            return 'tool_error:' + name
    return None


def review_check(date, post_path, src, policy):
    """문지기 쪽(루틴이 못 쓰는 곳)에 그날의 검토 접수 기록이 있으면: 지적마다 결정이 있어야 하고,
    받아들인 지적의 문장은 최종 글에 남아 있으면 안 된다."""
    trust = os.path.join(HERE, 'reviews', date + '.json')
    if not os.path.isfile(trust):
        return None, 'not_reviewed'
    rev = json.load(open(trust, encoding='utf-8'))
    dec_path = os.path.join(src, 'verification', date + '.review.json')
    try:
        dec = json.load(open(dec_path, encoding='utf-8')) if os.path.isfile(dec_path) else {}
    except ValueError:
        return 'review_bad_decisions', 'reviewed'
    body = text_of(post_path)
    for f in rev['findings']:
        d = dec.get(f['id'])
        if not isinstance(d, dict) or d.get('verdict') not in ('accepted', 'rejected'):
            return 'review_undecided:' + f['id'], 'reviewed'
        first = (rev.get('first_seen') or {}).get(f['id'])
        if first and first != d['verdict']:
            return 'decision_changed:' + f['id'], 'reviewed'
        if d['verdict'] == 'rejected':
            if d.get('reason') not in policy['reject_reasons']:
                return 'reject_without_reason:' + f['id'], 'reviewed'
            continue
        if ' '.join(f['quote'].split()) in body:
            return 'accepted_fix_missing:' + f['id'], 'reviewed'
        if f.get('material'):
            ev = d.get('evidence') or {}
            p = os.path.normpath(os.path.join(src, str(ev.get('path', ''))))
            if (not p.startswith(os.path.join(src, 'data') + os.sep) or not os.path.isfile(p)
                    or sha(p) != ev.get('sha256') or str(ev.get('needle', '\0')) not in open(p, encoding='utf-8', errors='replace').read()):
                return 'evidence_missing:' + f['id'], 'reviewed'
    return None, 'reviewed'


def judge_daily(rel, src, policy):
    date = os.path.basename(rel)[:-5]
    rec = os.path.join(src, 'verification', date + '.json')
    if not os.path.isfile(rec):
        return 'no_record', ''
    try:
        post = (json.load(open(rec, encoding='utf-8')).get('post') or {})
    except ValueError:
        return 'bad_record', ''
    if post.get('path') != rel or post.get('sha256') != sha(os.path.join(src, rel)):
        return 'hash_mismatch', ''
    why = rerun(rel, src, policy)
    if why:
        return why, ''
    why, state = review_check(date, os.path.join(src, rel), src, policy)
    return why, state


def cmd_judge(src, prev, out):
    policy = json.load(open(os.path.join(HERE, 'policy.json'), encoding='utf-8'))
    pinned = json.load(open(os.path.join(HERE, 'pinned.json'), encoding='utf-8'))
    classes = [(c['name'], re.compile(c['pattern'])) for c in policy['classes']]
    if os.path.exists(out):
        shutil.rmtree(out)
    verdict, manifest, files = {}, {}, []
    for root, dirs, names in os.walk(src):
        dirs[:] = [d for d in dirs if d != '.git']
        for name in names:
            full = os.path.join(root, name)
            files.append((os.path.relpath(full, src), full))

    def put(rel, path):
        dst = os.path.join(out, rel)
        os.makedirs(os.path.dirname(dst) or out, exist_ok=True)
        shutil.copyfile(path, dst)
        manifest[rel] = sha(dst)

    def keep_prev(rel):
        old = os.path.join(prev, rel)
        if os.path.isfile(old) and not os.path.islink(old):
            put(rel, old)

    daily_ok, daily_texts = [], {}
    for rel, full in sorted(files):
        cls = next((n for n, rx in classes if rx.match(rel)), None)
        if os.path.islink(full):
            verdict[rel] = ['hold', 'symlink']
            continue
        if cls is None:
            verdict[rel] = ['drop', 'unknown_path']          # 알려지지 않은 경로는 싣지 않는다
            continue
        if cls == 'daily':
            daily_texts[rel] = text_of(full)
            # 이미 실린 바이트라도 매번 다시 판정한다 — 예전에 통과시킨 것이 지금 기준으로도 통과하는지.
            same = os.path.isfile(os.path.join(prev, rel)) and sha(os.path.join(prev, rel)) == sha(full)
            why, state = judge_daily(rel, src, policy)
            if why and same:
                verdict[rel] = ['withdraw', why]          # 실려 있는 바로 그 판이 떨어졌다 → 내린다
            elif why:
                verdict[rel] = ['hold', why]
                keep_prev(rel)
            else:
                verdict[rel] = ['publish', state or 'ok']
                put(rel, full)
                daily_ok.append(rel)
        elif cls == 'chrome':
            if pinned.get(rel) == sha(full):
                verdict[rel] = ['publish', 'pinned']
                put(rel, full)
            else:
                verdict[rel] = ['hold', 'chrome_not_pinned']
                keep_prev(rel)
    # 일간이 아닌 글: 일간 표식이 있거나, 싣지 않는 일간 글과 본문이 겹치면 싣지 않는다
    held_daily = {r: t for r, t in daily_texts.items() if r not in daily_ok}
    for rel, full in sorted(files):
        cls = next((n for n, rx in classes if rx.match(rel)), None)
        if cls != 'news' or os.path.islink(full):
            continue
        raw = open(full, encoding='utf-8', errors='replace').read()
        if any(m in raw for m in policy['daily_markers'][:1]):
            verdict[rel] = ['hold', 'daily_marker_outside_daily']
            keep_prev(rel)
            continue
        sh = shingles(text_of(full))
        dup = next((r for r, t in held_daily.items()
                    if sh and len(sh & shingles(t)) / max(1, len(sh | shingles(t))) >= policy['dup_threshold']), None)
        if dup:
            verdict[rel] = ['hold', 'copy_of_held_daily:' + dup]
            keep_prev(rel)
            continue
        verdict[rel] = ['publish', 'ok']
        put(rel, full)
    # 목록은 원본을 옮기지 않고, 실리는 글만으로 다시 만든다. 글자 칸에 태그가 있으면 그 항목을 뺀다.
    lst = os.path.join(src, 'posts.json')
    items = []
    try:
        for it in json.load(open(lst, encoding='utf-8')):
            date, title = str(it.get('date', '')), str(it.get('title', ''))
            if set(it) - {'date', 'title'} or '<' in title or '>' in title or not re.fullmatch(r'\d{4}-\d{2}-\d{2}', date):
                continue
            if os.path.isfile(os.path.join(out, 'posts', date + '.html')):
                items.append({'date': date, 'title': title})
        verdict['posts.json'] = ['publish', 'rebuilt %d' % len(items)]
    except (OSError, ValueError):
        verdict['posts.json'] = ['hold', 'bad_list']
        items = None
    if items is None:
        keep_prev('posts.json')
    else:
        os.makedirs(out, exist_ok=True)
        json.dump(items, open(os.path.join(out, 'posts.json'), 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
        manifest['posts.json'] = sha(os.path.join(out, 'posts.json'))
    json.dump({'verdict': verdict, 'manifest': manifest}, open(out + '.verdict.json', 'w'), ensure_ascii=False, indent=1)
    for rel, (v, why) in sorted(verdict.items()):
        if v != 'drop' or not rel.startswith(('.github', 'scripts', 'verification', 'probe')):
            print('%-30s %-8s %s' % (rel, v, why))
    return 0


def cmd_seal(out):
    doc = json.load(open(out + '.verdict.json', encoding='utf-8'))
    seen = set()
    for root, dirs, files in os.walk(out):
        for name in files:
            rel = os.path.relpath(os.path.join(root, name), out)
            seen.add(rel)
            if doc['manifest'].get(rel) != sha(os.path.join(root, name)):
                print('seal: mismatch ' + rel)
                return 1
    if seen != set(doc['manifest']):
        print('seal: file set differs')
        return 1
    print('seal: ok %d files' % len(seen))
    return 0


def cmd_fresh(src_git, judged, last):
    """발행 직전: 판정한 원본이 마지막으로 발행한 원본보다 **오래됐으면** 거부한다(오래된 실행의 덮어쓰기)."""
    if not last or last == judged:
        print('fresh: ok (same or first)')
        return 0
    r = subprocess.run(['git', '-C', src_git, 'merge-base', '--is-ancestor', last, judged])
    print('fresh: ' + ('ok' if r.returncode == 0 else 'STALE — judged %s is not newer than published %s' % (judged[:8], last[:8])))
    return 0 if r.returncode == 0 else 1


if __name__ == '__main__':
    a = sys.argv[1:]
    sys.exit({'judge': lambda: cmd_judge(*a[1:4]), 'seal': lambda: cmd_seal(a[1]),
              'fresh': lambda: cmd_fresh(*a[1:4])}[a[0]]())
