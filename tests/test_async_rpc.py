import pytest

from mm_eth import async_rpc

pytestmark = pytest.mark.anyio


async def test_eth_block_number(mainnet, mainnet_ws, proxies):
    res = await async_rpc.eth_block_number(mainnet, proxies=proxies)
    assert res.unwrap() > 9_000_000

    res = await async_rpc.eth_block_number(mainnet_ws)
    assert res.unwrap() > 9_000_000


async def test_eth_get_balance(mainnet, address_bnb, proxies):
    res = await async_rpc.eth_get_balance(mainnet, address_bnb, proxies=proxies)
    assert res.unwrap() > 1
