"""시험용 근거 기록 — 작성자(루틴)가 낼 것을 대신 적은 것이다. 가설마다 「어느 계열을, 언제부터, 어떤 산식으로」.
가설을 세운 날 원장의 support/invalidation 문구를 읽고 옮겼다. 값은 하나도 적지 않는다(고른 기준만 예외)."""
SP = 'indices.S&P 500'
R = {
 # ── 아래 셋은 독립 표본(11/03~11/06 글)용 — 세운 날 원장의 support 문구만 보고 적었다(글의 문단은 보지 않았다)
 'us-2026-10-29-megacap-ai-monetization-rotation': dict(type='relative_return', legs=['indices.Russell 2000'], bench='indices.Nasdaq', start='2026-10-29',
     criterion=dict(basis='computed', rows=5, n=20, window_end='2026-10-28')),
 'us-2026-11-02-oil-relief-curve-flattening': dict(type='spread_change', a='yields.10Y', b='yields.2Y', start='2026-11-02',
     criterion=dict(basis='computed', rows=3, n=20, window_end='2026-11-02'),
     extras=[dict(label='WTI 기준 가격', formula='level', series='commodities.WTI', on='2026-11-02', unit='level')]),
 'us-2026-11-03-memory-apple-cost-vs-kioxia-peak': dict(type='relative_return', legs=['memory.Micron', 'memory.Western Digital', 'memory.Seagate'], bench='indices.Nasdaq', start='2026-11-03',
     criterion=dict(basis='computed', rows=3, n=20, window_end='2026-11-03')),
 # 산식 어휘(relative_return·spread_change) 밖이라 적지 못한 가설: 10-27(조건 세션 평균), 10-28(FRED 기대인플레), 10-30(두 양의 동시 조건)
 'us-2026-11-04-datacenter-politics-power-overreaction': dict(type='relative_return', legs=['ai_infra.Vertiv', 'ai_infra.GE Vernova'], bench=SP, start='2026-11-04',
     criterion=dict(basis='computed', rows=4, n=20, window_end='2026-11-04')),
 'us-2026-11-05-ai-chip-crash-degross-vs-rerating': dict(type='relative_return', legs=['sectors.Technology'], bench=SP, start='2026-11-05',
     criterion=dict(basis='computed', rows=5, n=20, window_end='2026-11-05'),
     extras=[dict(label='2년물 누적 변화', formula='bp_change', series='yields.2Y', start='2026-11-05'), dict(label='금리 재료 한도', formula='chosen', value=25, unit='bp')]),
 'us-2026-11-06-payrolls-front-end-flattening-vs-riskoff': dict(type='spread_change', a='yields.10Y', b='yields.2Y', start='2026-11-06',
     criterion=dict(basis='computed', rows=5, n=20, window_end='2026-11-06')),
 'us-2026-11-09-nvidia-governance-discount-persist': dict(type='relative_return', legs=['memory.Nvidia'], bench=SP, start='2026-11-09',
     criterion=dict(basis='computed', rows=5, n=20, window_end='2026-11-09')),
 'us-2026-11-10-ai-power-softbank-order-risk': dict(type='relative_return', legs=['ai_infra.Vertiv', 'ai_infra.GE Vernova'], bench=SP, start='2026-11-10',
     criterion=dict(basis='computed', rows=5, n=20, window_end='2026-11-10'),
     extras=[dict(label='2년물 누적 변화', formula='bp_change', series='yields.2Y', start='2026-11-10'), dict(label='금리 재료 한도', formula='chosen', value=25, unit='bp')]),
 'us-2026-11-11-memory-coreweave-financing-relief-vs-beta-bounce': dict(type='relative_return', legs=['memory.Micron', 'memory.Western Digital', 'memory.Seagate'], bench=SP, start='2026-11-11',
     criterion=dict(basis='computed', rows=4, n=20, window_end='2026-11-11'),
     extras=[dict(label='2년물 누적 변화', formula='bp_change', series='yields.2Y', start='2026-11-10'), dict(label='금리 재료 한도', formula='chosen', value=25, unit='bp')]),
 'us-2026-11-12-energy-iran-duration-vs-headline-bounce': dict(type='relative_return', legs=['sectors.Energy'], bench=SP, start='2026-11-12',
     criterion=dict(basis='computed', rows=5, n=20, window_end='2026-11-12'),
     extras=[dict(label='WTI 누적 등락률', formula='pct_change', series='commodities.WTI', start='2026-11-12')]),
 'us-2026-11-13-ppi-curve-long-end-steepening-vs-front-end-hikes': dict(type='spread_change', a='yields.10Y', b='yields.2Y', start='2026-11-13',
     criterion=dict(basis='computed', rows=5, n=20, window_end='2026-11-13', skip_end=['2026-11-12'])),
 'us-2026-11-16-ai-hardware-derisking-vs-policy-reprice': dict(type='relative_return', legs=['sectors.Technology'], bench=SP, start='2026-11-16',
     criterion=dict(basis='computed', rows=5, n=20, window_end='2026-11-16'),
     extras=[dict(label='금리 하락 한도', formula='chosen', value=20, unit='bp')]),
}


def record(date, hyp_ids):
    """그 날짜 글에 실린 가설들의 근거 기록. 끝 날짜만 그날로 채운다."""
    import copy
    items = []
    for h in hyp_ids:
        if h in R:
            it = copy.deepcopy(R[h])
            it.update(hypothesis=h, end=date)
            for x in it.get('extras') or []:
                if x['formula'] in ('bp_change', 'pct_change'):
                    x['end'] = date
            items.append(it)
    return {'format': 'judgment-evidence/1', 'date': date, 'items': items}
