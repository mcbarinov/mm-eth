import pytest
from mm_std import random_choice

from mm_eth import ethernodes


@pytest.mark.skip(reason="It's time to delete ethernodes at all")
def test_search_nodes(proxies):
    res = ethernodes.search_nodes(offset=100, proxy=random_choice(proxies))
    assert res.is_ok() and res.unwrap().records_total > 1000 and len(res.unwrap().data) == 100
