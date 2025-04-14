import json
import string
from collections.abc import Sequence
from typing import Any

import eth_utils
import websockets
from mm_std import DataResult, http_request


async def rpc_call(
    node: str,
    method: str,
    params: Sequence[object],
    timeout: float,
    proxy: str | None,
    id_: int = 1,
) -> DataResult[Any]:
    data = {"jsonrpc": "2.0", "method": method, "params": params, "id": id_}
    if node.startswith("http"):
        return await _http_call(node, data, timeout, proxy)
    return await _ws_call(node, data, timeout)


async def _http_call(node: str, data: dict[str, object], timeout: float, proxy: str | None) -> DataResult[Any]:
    res = await http_request(node, method="POST", proxy=proxy, timeout=timeout, json=data)
    if res.is_error():
        return res.to_data_result_err()
    try:
        parsed_body = res.parse_json_body()
        err = parsed_body.get("error", {}).get("message", "")
        if err:
            return res.to_data_result_err(f"service_error: {err}")
        if "result" in parsed_body:
            return res.to_data_result_ok(parsed_body["result"])
        return res.to_data_result_err("unknown_response")
    except Exception as err:
        return res.to_data_result_err(f"exception: {err}")


async def _ws_call(node: str, data: dict[str, object], timeout: float) -> DataResult[Any]:
    try:
        async with websockets.connect(node, timeout=timeout) as ws:
            await ws.send(json.dumps(data))
            response = json.loads(await ws.recv())

        err = response.get("error", {}).get("message", "")
        if err:
            return DataResult(err=f"service_error: {err}", data=response)
        if "result" in response:
            return DataResult(ok=response["result"], data=response)
        return DataResult(err="unknown_response", data=response)
    except TimeoutError:
        return DataResult(err="timeout")
    except Exception as err:
        return DataResult(err=f"exception: {err}")


async def eth_block_number(node: str, timeout: int = 10, proxy: str | None = None) -> DataResult[int]:
    return (await rpc_call(node, "eth_blockNumber", [], timeout, proxy)).map(hex_str_to_int)


async def eth_get_balance(node: str, address: str, timeout: int = 10, proxy: str | None = None) -> DataResult[int]:
    return (await rpc_call(node, "eth_getBalance", [address, "latest"], timeout, proxy)).map(hex_str_to_int)


async def erc20_balance(
    node: str,
    token_address: str,
    user_address: str,
    timeout: float = 7.0,
    proxy: str | None = None,
) -> DataResult[int]:
    data = "0x70a08231000000000000000000000000" + user_address[2:]
    params = [{"to": token_address, "data": data}, "latest"]
    return (await rpc_call(node, "eth_call", params, timeout, proxy)).map(hex_str_to_int)


async def erc20_name(node: str, token_address: str, timeout: float = 7.0, proxy: str | None = None) -> DataResult[str]:
    params = [{"to": token_address, "data": "0x06fdde03"}, "latest"]
    return (await rpc_call(node, "eth_call", params, timeout, proxy)).map(_normalize_str)


async def erc20_symbol(node: str, token_address: str, timeout: float = 7.0, proxy: str | None = None) -> DataResult[str]:
    params = [{"to": token_address, "data": "0x95d89b41"}, "latest"]
    return (await rpc_call(node, "eth_call", params, timeout, proxy)).map(_normalize_str)


async def erc20_decimals(node: str, token_address: str, timeout: float = 7.0, proxy: str | None = None) -> DataResult[int]:
    params = [{"to": token_address, "data": "0x313ce567"}, "latest"]
    res = await rpc_call(node, "eth_call", params, timeout, proxy)
    if res.is_err():
        return res
    try:
        if res.unwrap() == "0x":
            return DataResult(err="no_decimals", data=res.data)
        value = res.unwrap()
        result = eth_utils.to_int(hexstr=value[0:66]) if len(value) > 66 else eth_utils.to_int(hexstr=value)
        return DataResult(ok=result, data=res.data)
    except Exception as e:
        return DataResult(err=f"exception: {e}", data=res.data)


def hex_str_to_int(value: str) -> int:
    return int(value, 16)


def _normalize_str(value: str) -> str:
    return "".join(filter(lambda x: x in string.printable, eth_utils.to_text(hexstr=value))).strip()
