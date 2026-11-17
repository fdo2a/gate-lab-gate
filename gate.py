#!/usr/bin/env python3
"""실험용 문지기. judge: 원본(src)을 **자료로만** 읽어 판정하고 내보낼 트리(out)를 만든다 — src 의 코드는 실행하지 않는다.
seal: out 의 바이트가 판정 때 적은 해시와 같은지 다시 본다(발행 작업에서)."""
import hashlib, json, os, re, shutil, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__))


def sha(path):
    with open(path, 'rb') as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def judge_post(src, rel, policy):
    """→ (verdict, reason). verdict: publish | hold"""
    date = os.path.basename(rel)[:-5]
    rec_path = os.path.join(src, 'verification', date + '.json')
    if not os.path.isfile(rec_path):
        return 'hold', 'no_record'
    try:
        rec = json.load(open(rec_path, encoding='utf-8'))
    except ValueError:
        return 'hold', 'bad_record'
    post = rec.get('post') or {}
    if post.get('path') != rel or post.get('sha256') != sha(os.path.join(src, rel)):
        return 'hold', 'hash_mismatch'
    have = {g.get('name'): g.get('status') for g in rec.get('gates') or [] if isinstance(g, dict)}
    for name in policy['required']:
        if have.get(name) not in ('pass', 'warn'):
            return 'hold', 'required_not_passed:' + name
        # 기록을 믿지 않고 문지기의 검사기로 다시 돈다
        try:
            r = subprocess.run([sys.executable, '-I', '-S', os.path.join(HERE, 'trusted', name + '.py'),
                                os.path.join(src, rel)], capture_output=True, text=True, timeout=60)
        except Exception:  # noqa: BLE001
            return 'hold', 'tool_error:' + name
        if r.returncode == 1 and r.stdout.startswith('fail'):
            return 'hold', 'gate_failed:' + name
        if r.returncode != 0:
            return 'hold', 'tool_error:' + name
    return 'publish', 'ok'


def cmd_judge(src, prev, out):
    policy = json.load(open(os.path.join(HERE, 'policy.json'), encoding='utf-8'))
    gated = re.compile(policy['gated'])
    if os.path.exists(out):
        shutil.rmtree(out)
    verdict, manifest = {}, {}
    for root, dirs, files in os.walk(src):
        dirs[:] = [d for d in dirs if d != '.git']
        for name in files:
            full = os.path.join(root, name)
            rel = os.path.relpath(full, src)
            if any(rel == s or rel.startswith(s + '/') for s in policy['strip']):
                continue
            if os.path.islink(full):
                verdict[rel] = ['hold', 'symlink']
                continue
            dst = os.path.join(out, rel)
            in_gated_dir = rel.startswith(policy['gated_dir'])
            if in_gated_dir:
                # 보호 폴더는 허용 목록 방식: 이름이 규칙에 맞고 판정이 publish 인 것만 싣는다
                v, why = judge_post(src, rel, policy) if gated.match(rel) else ('hold', 'not_a_gated_name')
                verdict[rel] = [v, why]
                if v != 'publish':
                    old = os.path.join(prev, rel)
                    if gated.match(rel) and os.path.isfile(old):       # 직전에 실린 판을 유지
                        os.makedirs(os.path.dirname(dst), exist_ok=True)
                        shutil.copyfile(old, dst)
                        manifest[rel] = sha(dst)
                    continue
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.copyfile(full, dst)
            manifest[rel] = sha(dst)
    # 목록에서 실리지 않는 글을 뺀다
    lst = os.path.join(out, 'posts.json')
    if os.path.isfile(lst):
        items = json.load(open(lst, encoding='utf-8'))
        keep = [it for it in items if os.path.isfile(os.path.join(out, 'posts', str(it.get('date')) + '.html'))]
        json.dump(keep, open(lst, 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
        manifest['posts.json'] = sha(lst)
    json.dump({'verdict': verdict, 'manifest': manifest}, open(out + '.verdict.json', 'w'), ensure_ascii=False, indent=1)
    for rel, (v, why) in sorted(verdict.items()):
        print('%-28s %s  %s' % (rel, v, why))
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


if __name__ == '__main__':
    a = sys.argv[1:]
    sys.exit(cmd_judge(*a[1:4]) if a[0] == 'judge' else cmd_seal(a[1]))
