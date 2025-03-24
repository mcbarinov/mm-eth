import pytest
from mm_crypto_utils import random_proxy
from mm_std import Ok

from mm_eth import ens

pytestmark = pytest.mark.anyio


def test_get_name_exists(mainnet, proxies):
    address = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"
    assert ens.get_name(mainnet, address, proxy=random_proxy(proxies)) == Ok("vitalik.eth")


def test_get_name_non_exists(mainnet, proxies):
    address = "0x743997F620846ab4CE946CBe3f5e5b5c51921D6E"  # random empty address
    assert ens.get_name(mainnet, address, proxy=random_proxy(proxies)) == Ok(None)


async def test_async_get_name_exists(mainnet, proxies):
    address = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"
    assert await ens.async_get_name(mainnet, address, proxy=random_proxy(proxies)) == Ok("vitalik.eth")


async def test_async_get_name_non_exists(mainnet, proxies):
    address = "0x743997F620846ab4CE946CBe3f5e5b5c51921D6E"  # random empty address
    assert await ens.async_get_name(mainnet, address, proxy=random_proxy(proxies)) == Ok(None)
