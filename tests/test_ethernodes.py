from mm_std import random_choice

from mm_eth import ethernodes


def test_search_nodes(mm_proxies):
    res = ethernodes.search_nodes(offset=100, proxy=random_choice(mm_proxies))
    assert res.is_ok() and res.ok.records_total > 1000 and len(res.ok.data) == 100
