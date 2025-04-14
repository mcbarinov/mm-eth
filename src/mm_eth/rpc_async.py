import json
import string
from collections.abc import Sequence
from typing import Any

import ens.utils
import eth_utils
import websockets
from mm_std import DataResult, http_request

DEFAULT_TIMEOUT = 7.0


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


async def eth_block_number(node: str, timeout: float = DEFAULT_TIMEOUT, proxy: str | None = None) -> DataResult[int]:
    return (await rpc_call(node, "eth_blockNumber", [], timeout, proxy)).map(_hex_str_to_int)


async def eth_get_balance(node: str, address: str, timeout: float = DEFAULT_TIMEOUT, proxy: str | None = None) -> DataResult[int]:
    return (await rpc_call(node, "eth_getBalance", [address, "latest"], timeout, proxy)).map(_hex_str_to_int)


async def erc20_balance(
    node: str, token_address: str, user_address: str, timeout: float = DEFAULT_TIMEOUT, proxy: str | None = None
) -> DataResult[int]:
    data = "0x70a08231000000000000000000000000" + user_address[2:]
    params = [{"to": token_address, "data": data}, "latest"]
    return (await rpc_call(node, "eth_call", params, timeout, proxy)).map(_hex_str_to_int)


async def erc20_name(
    node: str, token_address: str, timeout: float = DEFAULT_TIMEOUT, proxy: str | None = None
) -> DataResult[str]:
    params = [{"to": token_address, "data": "0x06fdde03"}, "latest"]
    return (await rpc_call(node, "eth_call", params, timeout, proxy)).map(_normalize_str)


async def erc20_symbol(
    node: str, token_address: str, timeout: float = DEFAULT_TIMEOUT, proxy: str | None = None
) -> DataResult[str]:
    params = [{"to": token_address, "data": "0x95d89b41"}, "latest"]
    return (await rpc_call(node, "eth_call", params, timeout, proxy)).map(_normalize_str)


async def erc20_decimals(
    node: str, token_address: str, timeout: float = DEFAULT_TIMEOUT, proxy: str | None = None
) -> DataResult[int]:
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


ENS_REGISTRY_ADDRESS: str = "0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e"
FUNC_SELECTOR_RESOLVER: str = "0x0178b8bf"  # resolver(bytes32)
FUNC_SELECTOR_NAME: str = "0x691f3431"  # name(bytes32)


async def ens_name(node: str, address: str, timeout: float = DEFAULT_TIMEOUT, proxy: str | None = None) -> DataResult[str | None]:
    checksum_addr = eth_utils.to_checksum_address(address)
    reverse_name = checksum_addr.lower()[2:] + ".addr.reverse"
    name_hash_hex = ens.utils.normal_name_to_hash(reverse_name).hex()

    resolver_data = FUNC_SELECTOR_RESOLVER + name_hash_hex

    resolver_params = [{"to": ENS_REGISTRY_ADDRESS, "data": resolver_data}, "latest"]

    resolver_res = await rpc_call(node, method="eth_call", params=resolver_params, timeout=timeout, proxy=proxy)
    if resolver_res.is_err():
        return resolver_res

    if resolver_res.is_ok() and len(resolver_res.unwrap()) != 66:
        return DataResult(ok=None, data={"revolver_response": resolver_res.dict()})

    resolver_address = eth_utils.to_checksum_address("0x" + resolver_res.unwrap()[-40:])

    name_data: str = FUNC_SELECTOR_NAME + name_hash_hex
    name_params = [{"to": resolver_address, "data": name_data}, "latest"]

    name_res: DataResult[str] = await rpc_call(node, "eth_call", name_params, timeout=timeout, proxy=proxy)

    if name_res.is_err():
        return DataResult(
            err=name_res.unwrap_err(), data={"resolver_response": resolver_res.dict(), "name_response": name_res.dict()}
        )

    if name_res.unwrap() == "0x":
        return DataResult(
            ok=None,
            data={"resolver_response": resolver_res.dict(), "name_response": name_res.dict()},
            ok_is_none=True,
        )

    try:
        hex_data = name_res.unwrap()
        length_hex = hex_data[66:130]
        str_len = int(length_hex, 16) * 2
        name_hex = hex_data[130 : 130 + str_len]
        return DataResult(
            ok=bytes.fromhex(name_hex).decode("utf-8"),
            data={"resolver_response": resolver_res.dict(), "name_response": name_res.dict()},
        )
    except Exception as e:
        return DataResult(
            err="exception",
            data={"resolver_response": resolver_res.dict(), "name_response": name_res.dict(), "exception": str(e)},
        )


def _hex_str_to_int(value: str) -> int:
    return int(value, 16)


def _normalize_str(value: str) -> str:
    return "".join(filter(lambda x: x in string.printable, eth_utils.to_text(hexstr=value))).strip()
