import json
from typing import Any

import websockets
from mm_crypto_utils import Nodes, Proxies, random_node, random_proxy
from mm_std import Err, Ok, Result, ahr

from mm_eth.utils import hex_str_to_int


async def rpc_call(
    *,
    nodes: Nodes,
    method: str,
    params: list[object],
    id_: int = 1,
    timeout: int = 10,
    proxies: Proxies = None,
    attempts: int = 1,
) -> Result[Any]:
    data = {"jsonrpc": "2.0", "method": method, "params": params, "id": id_}
    res: Result[Any] = Err("not started yet")
    for _ in range(attempts):
        node = random_node(nodes)
        res = (
            await _http_call(node, data, timeout, random_proxy(proxies))
            if node.startswith("http")
            else await _ws_call(node, data, timeout)
        )
        if isinstance(res, Ok):
            return res
    return res


async def _http_call(node: str, data: dict[str, object], timeout: int, proxy: str | None) -> Result[Any]:
    res = await ahr(node, method="POST", proxy=proxy, timeout=timeout, params=data, json_params=True)
    if res.is_error():
        return res.to_err_result()
    try:
        err = res.json.get("error", {}).get("message", "")
        if err:
            return res.to_err_result(f"service_error: {err}")
        if "result" in res.json:
            return res.to_ok_result(res.json["result"])
        return res.to_err_result("unknown_response")
    except Exception as err:
        return res.to_err_result(f"exception: {err}")


async def _ws_call(node: str, data: dict[str, object], timeout: int) -> Result[Any]:
    try:
        async with websockets.connect(node, timeout=timeout) as ws:
            await ws.send(json.dumps(data))
            response = json.loads(await ws.recv())

        err = response.get("error", {}).get("message", "")
        if err:
            return Err(f"service_error: {err}")
        if "result" in response:
            return Ok(response["result"], response)
        return Err(f"unknown_response: {response}")
    except TimeoutError:
        return Err("timeout")
    except Exception as err:
        return Err(f"exception: {err}")


async def eth_block_number(rpc_urls: Nodes, timeout: int = 10, proxies: Proxies = None, attempts: int = 1) -> Result[int]:
    return (
        await rpc_call(
            nodes=rpc_urls,
            method="eth_blockNumber",
            params=[],
            timeout=timeout,
            proxies=proxies,
            attempts=attempts,
        )
    ).and_then(hex_str_to_int)


async def eth_get_balance(
    rpc_urls: Nodes, address: str, timeout: int = 10, proxies: Proxies = None, attempts: int = 1
) -> Result[int]:
    return (
        await rpc_call(
            nodes=rpc_urls,
            method="eth_getBalance",
            params=[address, "latest"],
            timeout=timeout,
            proxies=proxies,
            attempts=attempts,
        )
    ).and_then(hex_str_to_int)
