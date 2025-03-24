import pytest

from mm_eth import erc20

pytestmark = pytest.mark.anyio


def test_get_balance(mainnet, address_tether, address_bnb, proxies):
    res = erc20.get_balance(mainnet, token_address=address_tether, user_address=address_bnb, proxies=proxies)
    assert res.unwrap() > 1_000_000


async def test_async_get_balance(mainnet, address_tether, address_bnb, proxies):
    res = await erc20.async_get_balance(mainnet, token_address=address_tether, user_address=address_bnb, proxies=proxies)
    assert res.unwrap() > 1_000_000
