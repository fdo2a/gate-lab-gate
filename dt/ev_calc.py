"""판단 근거 재계산 — 보호된 일별 종가 이력(market.jsonl)만 읽는다. 산식은 여기 적힌 몇 가지뿐이다."""
import json


def load(path):
    rows = [json.loads(l) for l in open(path, encoding='utf-8') if l.strip()]
    return {r['report_date']: r for r in rows}, [r['report_date'] for r in rows]


def level(H, series, date):
    grp, key = series.split('.', 1)
    v = H[date].get(grp, {}).get(key)
    if v is None:
        raise KeyError('%s on %s' % (series, date))
    return v


def pct(H, series, start, end):
    return (level(H, series, end) / level(H, series, start) - 1) * 100


def rel(H, legs, bench, start, end):
    """다리들의 단순평균 누적 등락률 − 기준 지수의 누적 등락률 (%p)."""
    return sum(pct(H, s, start, end) for s in legs) / len(legs) - pct(H, bench, start, end)


def spread(H, a, b, date):
    """두 금리의 차이(bp) — 예: 10Y − 2Y."""
    return (level(H, a, date) - level(H, b, date)) * 100


def crit_rel(H, dates, legs, bench, rows, n, window_end):
    """끝점이 window_end 까지인 최근 n개 구간(각 rows 행 길이)의 상대수익률 차이 절댓값 평균."""
    i = dates.index(window_end)
    if i - n + 1 - rows < 0:
        raise KeyError('not enough rows for %d windows' % n)
    xs = [abs(rel(H, legs, bench, dates[j - rows], dates[j])) for j in range(i - n + 1, i + 1)]
    return sum(xs) / len(xs)


def crit_spread(H, dates, a, b, rows, n, window_end, skip_end=()):
    """끝점이 window_end 까지인 최근 n개 구간의 스프레드 변화 절댓값 평균(bp). skip_end 에 든 끝점은 건너뛰고 n개를 채운다."""
    j, xs = dates.index(window_end), []
    while len(xs) < n and j - rows >= 0:
        if dates[j] not in skip_end:
            xs.append(abs(spread(H, a, b, dates[j]) - spread(H, a, b, dates[j - rows])))
        j -= 1
    if len(xs) < n:
        raise KeyError('not enough rows for %d windows' % n)
    return sum(xs) / len(xs)


def lead_count(H, dates, legs, bench, rows, n, window_end):
    """같은 n개 구간 가운데 다리가 기준 지수를 앞선 구간 수."""
    i = dates.index(window_end)
    return sum(1 for j in range(i - n + 1, i + 1) if rel(H, legs, bench, dates[j - rows], dates[j]) > 0)
