#!/usr/bin/env python3
"""판단 근거 확인 (작은 설계 실험).

보증하려는 것
  - 판단 문단(<p data-hypothesis="…">)의 수치마다, 작성자가 낸 근거 기록의 **입력·산식**으로 **보호된 종가 이력**에서
    문지기가 다시 계산한 값과 같은지. 같지 않거나, 기록이 없거나, 기록으로 설명되지 않는 수치가 있으면 보류.
  - 기준값과 시작일이 가설을 세운 날 원장에 적힌 것과 같은지(세운 뒤에 바뀌지 않았는지).
보증하지 못하는 것
  - 그 기준·산식을 고른 것이 투자 판단으로 적절한지. 숫자 없는 서술. 판단 문단 밖의 문장. 방향어(올랐다/내렸다)와
    부호가 맞는지(부호를 글자로 적은 수치만 본다). 보호된 이력이 원천과 같은지. 원장 자체(루틴이 쓴다)가 옳은지.

근거 기록은 **값이 아니라 조리법**이다 — 어느 계열을, 어느 날부터 어느 날까지, 어떤 산식으로. 값은 문지기가 만든다.
작성자가 낸 기록은 믿지 않는다: 기록이 가리키는 계열·날짜는 보호된 이력에 있어야 하고, 산식은 여기 적힌 것뿐이다.
"""
import json, os, re, sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import ev_calc as C  # noqa: E402

PARA = re.compile(r'<p\b[^>]*\bdata-hypothesis\s*=\s*"([^"]+)"[^>]*>(.*?)</p\s*>', re.S | re.I)
TAG = re.compile(r'<[^>]+>')
KIND_KO = {'observation': '외부 관측값', 'computed': '계산 결과', 'criterion_computed': '산식으로 낸 기준', 'criterion_chosen': '분석자가 고른 기준',
           'parameter': '산식의 매개값(구간 수·행 수)'}


def tokens(text, code):
    """고정 사본의 숫자 토크나이저를 그대로 쓴다(날짜는 가려진다)."""
    sys.path.insert(0, os.path.join(code, 'scripts'))
    from us import number_audit as N
    return N.tokens(text)


def _prev(dates, d):
    return dates[dates.index(d) - 1]


def derive(item, H, dates):
    """조리법 → [(이름, 갈래, 단위, 값)] . 계열·날짜가 이력에 없으면 KeyError."""
    out = []

    def add(label, kind, unit, value):
        out.append({'label': label, 'kind': kind, 'unit': unit, 'value': value})

    t, s, e = item['type'], item['start'], item['end']
    cr = item.get('criterion') or {}
    between = dates[dates.index(s) + 1:dates.index(e)]        # 시작일과 끝 날짜 사이의 날들

    def day(series, d, unit):
        """그 날 하루 변화(앞 행 대비)."""
        p = _prev(dates, d)
        return (C.level(H, series, d) - C.level(H, series, p)) * 100 if unit == 'bp' else C.pct(H, series, p, d)
    if t == 'relative_return':
        legs, bench = item['legs'], item['bench']
        for x in legs + [bench]:
            add('%s 종가(%s)' % (x, s), 'observation', 'level', C.level(H, x, s))
            add('%s 종가(%s)' % (x, e), 'observation', 'level', C.level(H, x, e))
            if s != e:
                add('%s 누적 등락률' % x, 'computed', '%', C.pct(H, x, s, e))
        for d in dict.fromkeys((s, e)):                     # 시작일·끝 날짜 하루 등락률과 그 차이
            for x in legs + [bench]:
                add('%s 하루 등락률(%s)' % (x, d), 'computed', '%', day(x, d, '%'))
            m = sum(day(x, d, '%') for x in legs) / len(legs)
            add('다리 단순평균 하루 등락률(%s)' % d, 'computed', '%', m)
            add('하루 차이(%s)' % d, 'computed', '%p', m - day(bench, d, '%'))
        if s != e:
            if len(legs) > 1:
                add('다리 단순평균 누적 등락률', 'computed', '%', sum(C.pct(H, x, s, e) for x in legs) / len(legs))
            r = C.rel(H, legs, bench, s, e)
            add('상대 차이', 'computed', '%p', r)
            for d in between:
                add('상대 차이(%s)' % d, 'computed', '%p', C.rel(H, legs, bench, s, d))
        if cr.get('basis') == 'computed':
            c = C.crit_rel(H, dates, legs, bench, cr['rows'], cr['n'], cr['window_end'])
            add('기준(절댓값 평균)', 'criterion_computed', '%p', c)
            add('구간 수', 'parameter', 'count', cr['n'])
            add('구간 길이', 'parameter', 'count', cr['rows'])
            add('다리가 앞선 구간 수', 'computed', 'count', C.lead_count(H, dates, legs, bench, cr['rows'], cr['n'], cr['window_end']))
            if s != e:
                add('기준까지 남은 거리', 'computed', '%p', round(c, 2) - abs(round(C.rel(H, legs, bench, s, e), 3)))
    elif t == 'spread_change':
        a, b = item['a'], item['b']
        for x in (a, b):
            add('%s(%s)' % (x, s), 'observation', '%', C.level(H, x, s))
            add('%s(%s)' % (x, e), 'observation', '%', C.level(H, x, e))
            if s != e:
                add('%s 변화' % x, 'computed', 'bp', (C.level(H, x, e) - C.level(H, x, s)) * 100)
        add('금리차(%s)' % s, 'computed', 'bp', C.spread(H, a, b, s))
        for d in dict.fromkeys((s, e)):
            for x in (a, b):
                add('%s 하루 변화(%s)' % (x, d), 'computed', 'bp', day(x, d, 'bp'))
            add('금리차 하루 변화(%s)' % d, 'computed', 'bp', C.spread(H, a, b, d) - C.spread(H, a, b, _prev(dates, d)))
            add('금리차(전 거래일, %s)' % d, 'computed', 'bp', C.spread(H, a, b, _prev(dates, d)))
        if s != e:
            add('금리차(%s)' % e, 'computed', 'bp', C.spread(H, a, b, e))
            add('금리차 변화', 'computed', 'bp', C.spread(H, a, b, e) - C.spread(H, a, b, s))
            for d in between:
                add('금리차 변화(%s)' % d, 'computed', 'bp', C.spread(H, a, b, d) - C.spread(H, a, b, s))
        if cr.get('basis') == 'computed':
            c = C.crit_spread(H, dates, a, b, cr['rows'], cr['n'], cr['window_end'], tuple(cr.get('skip_end') or ()))
            add('기준(절댓값 평균)', 'criterion_computed', 'bp', c)
            if s != e:
                add('기준까지 남은 거리', 'computed', 'bp', round(c, 2) - abs(round(C.spread(H, a, b, e) - C.spread(H, a, b, s), 2)))
            add('구간 수', 'parameter', 'count', cr['n'])
            add('구간 길이', 'parameter', 'count', cr['rows'])
    else:
        raise ValueError('모르는 산식 ' + str(t))
    for x in item.get('extras') or []:
        f = x['formula']
        if f in ('bp_change', 'pct_change'):
            unit = '%' if x['series'].startswith('yields.') else 'level'
            add(x['label'] + ' 시작 값', 'observation', unit, C.level(H, x['series'], x['start']))
            add(x['label'] + ' 끝 값', 'observation', unit, C.level(H, x['series'], x['end']))
        if f == 'bp_change':
            add(x['label'], 'computed', 'bp', (C.level(H, x['series'], x['end']) - C.level(H, x['series'], x['start'])) * 100)
        elif f == 'pct_change':
            add(x['label'], 'computed', '%', C.pct(H, x['series'], x['start'], x['end']))
        elif f == 'level':
            add(x['label'], 'observation', x.get('unit', 'level'), C.level(H, x['series'], x['on']))
        elif f == 'chosen':
            add(x['label'], 'criterion_chosen', x['unit'], x['value'])
        else:
            raise ValueError('모르는 산식 ' + str(f))
    return out


UNITS = {'%': ('%',), '%p': ('%p',), 'bp': ('bp',), 'level': ('', '달러'), 'count': ('',)}


def match(tok, cands):
    """수치 하나를 설명하는 후보 — 인쇄된 자릿수로 반올림해 같고, 단위가 맞고, 부호를 글자로 적었으면 부호도 같아야 한다."""
    for c in cands:
        if tok.unit not in UNITS[c['unit']]:
            continue
        if ('%.*f' % (tok.decimals, abs(c['value']))) != ('%.*f' % (tok.decimals, abs(tok.value))):
            continue
        if tok.sign and c['kind'] not in ('criterion_computed', 'criterion_chosen'):
            neg = tok.sign in '-−－–'
            if neg != (c['value'] < 0) and round(abs(c['value']), tok.decimals) != 0:
                continue
        return c
    return None


def check(post_text, record, history_path, ledger_rows, code, date):
    """→ {'reasons': [...], 'paragraphs': [...], 'human_judgment': [...]}"""
    out = {'reasons': [], 'paragraphs': [], 'human_judgment': [], 'tokens': 0, 'explained': 0}
    paras = PARA.findall(post_text)
    if not paras:
        return out
    try:
        H, dates = C.load(history_path)
    except Exception:
        out['reasons'].append('evidence_history_missing')
        return out
    if date not in H:
        out['reasons'].append('evidence_history_stale(last=%s)' % (dates[-1] if dates else None))
        return out
    items = {}
    if isinstance(record, dict) and record.get('date') == date:
        for it in record.get('items') or []:
            if isinstance(it, dict) and isinstance(it.get('hypothesis'), str):
                items.setdefault(it['hypothesis'], it)
    hyp = {r['id']: r for r in ledger_rows if r.get('type') == 'hypothesis'}
    for hid, inner in paras:
        text = re.sub(r'\s+', ' ', TAG.sub(' ', inner))
        toks = tokens(text, code)
        p = {'hypothesis': hid, 'tokens': len(toks), 'kinds': {}, 'unexplained': []}
        out['tokens'] += len(toks)
        it = items.get(hid)
        if it is None:
            out['reasons'].append('evidence_missing:' + hid)
            out['paragraphs'].append(p)
            continue
        if it.get('end') != date:
            out['reasons'].append('evidence_wrong_end:%s(%s)' % (hid, it.get('end')))
        try:
            cands = derive(it, H, dates)
        except (KeyError, ValueError, TypeError, IndexError, ZeroDivisionError) as exc:
            out['reasons'].append('evidence_input_missing:%s(%s)' % (hid, str(exc)[:60]))
            out['paragraphs'].append(p)
            continue
        # 세운 날 원장에 적힌 것과 같은가 — 시작일, 산식으로 낸 기준, 고른 기준
        reg = hyp.get(hid)
        if reg is None:
            out['reasons'].append('hypothesis_not_registered:' + hid)
        else:
            regtext = (reg.get('support') or '') + ' ' + (reg.get('invalidation') or '')
            if it.get('start') != reg.get('report_date'):
                out['reasons'].append('start_not_registered:%s(%s≠%s)' % (hid, it.get('start'), reg.get('report_date')))
            for c in cands:
                if c['kind'] == 'criterion_computed':
                    if not re.search(r'(?<![\d.])%s(?!\d)' % re.escape('%.2f' % abs(c['value'])), regtext):
                        out['reasons'].append('criterion_changed_since_registration:%s(%.2f)' % (hid, abs(c['value'])))
                elif c['kind'] == 'criterion_chosen':
                    shown = ('%g' % c['value'])
                    if not re.search(r'(?<![\d.])%s(?![\d.])' % re.escape(shown), regtext):
                        out['reasons'].append('criterion_not_registered:%s(%s%s)' % (hid, shown, c['unit']))
        for t in toks:
            c = match(t, cands)
            if c is None:
                p['unexplained'].append(t.raw)
                out['reasons'].append('unexplained_number:%s(%s)' % (hid, t.raw.strip()))
            else:
                out['explained'] += 1
                p['kinds'][c['kind']] = p['kinds'].get(c['kind'], 0) + 1
                if c['kind'] in ('criterion_computed', 'criterion_chosen'):
                    out['human_judgment'].append({'hypothesis': hid, 'number': t.raw.strip(), 'what': KIND_KO[c['kind']],
                                                  'machine_checked': '산식·입력으로 다시 계산해 일치, 세운 날 원장의 값과 일치' if c['kind'] == 'criterion_computed' else '세운 날 원장에 적힌 값과 일치(값 자체는 다시 계산할 수 없다)',
                                                  'not_checked': '이 기준·산식이 판단에 적절한가'})
        out['paragraphs'].append(p)
    for hid in items:
        if hid not in dict(paras):
            out['reasons'].append('evidence_for_absent_paragraph:' + hid)
    return out
