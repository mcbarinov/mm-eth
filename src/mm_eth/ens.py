from ens.utils import normal_name_to_hash
from mm_crypto_utils import Nodes, Proxies, random_node, random_proxy
from mm_std import Err, Ok, Result
from web3 import Web3

from mm_eth.async_rpc import rpc_call
from mm_eth.utils import get_w3

ENS_REGISTRY_ADDRESS: str = "0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e"
FUNC_SELECTOR_RESOLVER: str = "0x0178b8bf"  # resolver(bytes32)
FUNC_SELECTOR_NAME: str = "0x691f3431"  # name(bytes32)


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
        error = str(e)
        if not error:
            error = e.__class__.__qualname__
        return Err("exception: " + error)

    # async def async_get_name(rpc_url: str, address: str, timeout: float = 5, proxy: str | None = None) -> Result[str | None]:
    #     w3 = await get_async_w3(rpc_url, timeout=timeout, proxy=proxy)
    #     try:
    #         res = await w3.ens.name(w3.to_checksum_address(address))  # type: ignore[union-attr]
    #         return Ok(res)
    #     except Exception as e:
    #         error = str(e)
    #         if not error:
    #             error = e.__class__.__qualname__
    #         return Err("exception: " + error)
    #     finally:
    #         await w3.provider.disconnect()


async def get_name_async(rpc_url: str, address: str, timeout: float = 5, proxy: str | None = None) -> Result[str | None]:
    checksum_addr: str = Web3.to_checksum_address(address)
    reverse_name: str = checksum_addr.lower()[2:] + ".addr.reverse"
    name_hash_hex: str = normal_name_to_hash(reverse_name).hex()

    resolver_data: str = FUNC_SELECTOR_RESOLVER + name_hash_hex

    resolver_params = [{"to": ENS_REGISTRY_ADDRESS, "data": resolver_data}, "latest"]

    resolver_res: Result[str] = await rpc_call(
        nodes=rpc_url,
        method="eth_call",
        params=resolver_params,
        timeout=timeout,
        proxies=proxy,
        attempts=1,
    )
    if not isinstance(resolver_res, Ok) or len(resolver_res.ok) != 66:
        return Ok(None)

    resolver_address: str = Web3.to_checksum_address("0x" + resolver_res.ok[-40:])

    name_data: str = FUNC_SELECTOR_NAME + name_hash_hex
    name_params = [{"to": resolver_address, "data": name_data}, "latest"]

    name_res: Result[str] = await rpc_call(
        nodes=rpc_url,
        method="eth_call",
        params=name_params,
        timeout=timeout,
        proxies=proxy,
        attempts=1,
    )

    if isinstance(name_res, Err):
        return name_res
    if name_res.ok == "0x":
        return Ok(None)

    try:
        hex_data: str = name_res.ok
        length_hex: str = hex_data[66:130]
        str_len: int = int(length_hex, 16) * 2
        name_hex: str = hex_data[130 : 130 + str_len]
        return Ok(bytes.fromhex(name_hex).decode("utf-8"))
    except Exception as e:
        return Err(e)


async def get_name_with_retries_async(
    rpc_urls: Nodes, address: str, retries: int, timeout: float = 5, proxies: Proxies = None
) -> Result[str | None]:
    res: Result[str | None] = Err("not started yet")
    for _ in range(retries):
        res = await get_name_async(random_node(rpc_urls), address, timeout=timeout, proxy=random_proxy(proxies))
        if res.is_ok():
            return res
    return res
