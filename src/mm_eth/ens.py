from mm_crypto_utils import Nodes, Proxies, random_node, random_proxy
from mm_std import Err, Ok, Result

from mm_eth.utils import get_async_w3, get_w3


def get_name_with_retries(
    rpc_urls: Nodes, address: str, retries: int, timeout: float = 5, proxies: Proxies = None
) -> Result[str | None]:
    res: Result[str | None] = Err("not started yet")
    for _ in range(retries):
        res = get_name(random_node(rpc_urls), address, timeout=timeout, proxy=random_proxy(proxies))
        if res.is_ok():
            return res
    return res


def get_name(rpc_url: str, address: str, timeout: float = 5, proxy: str | None = None) -> Result[str | None]:
    try:
        w3 = get_w3(rpc_url, timeout=timeout, proxy=proxy)
        return Ok(w3.ens.name(w3.to_checksum_address(address)))  # type: ignore[union-attr]
    except Exception as e:
        return Err(e)


async def async_get_name(rpc_url: str, address: str, timeout: float = 5, proxy: str | None = None) -> Result[str | None]:
    try:
        w3 = await get_async_w3(rpc_url, timeout=timeout, proxy=proxy)
        res = await w3.ens.name(w3.to_checksum_address(address))  # type: ignore[union-attr]
        await w3.provider.disconnect()
        return Ok(res)
    except Exception as e:
        return Err(e)


async def async_get_name_with_retries(
    rpc_urls: Nodes, address: str, retries: int, timeout: float = 5, proxies: Proxies = None
) -> Result[str | None]:
    res: Result[str | None] = Err("not started yet")
    for _ in range(retries):
        res = await async_get_name(random_node(rpc_urls), address, timeout=timeout, proxy=random_proxy(proxies))
        if res.is_ok():
            return res
    return res
