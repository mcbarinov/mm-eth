import asyncio
import json
import string
from collections.abc import Sequence
from typing import Any

import ens.utils
import eth_utils
import pydash
import websockets
from eth_typing import BlockIdentifier
from mm_std import Result, http_request

TIMEOUT = 7.0


async def rpc_call(
    node: str,
    method: str,
    params: Sequence[object],
    timeout: float,
    proxy: str | None,
    id_: int = 1,
) -> Result[Any]:
    data = {"jsonrpc": "2.0", "method": method, "params": params, "id": id_}
    if node.startswith("http"):
        return await _http_call(node, data, timeout, proxy)
    return await _ws_call(node, data, timeout)


async def _http_call(node: str, data: dict[str, object], timeout: float, proxy: str | None) -> Result[Any]:
    res = await http_request(node, method="POST", proxy=proxy, timeout=timeout, json=data)
    if res.is_err():
        return res.to_err()
    try:
        parsed_body = res.parse_json_body()
        err = parsed_body.get("error", {}).get("message", "")
        if err:
            return res.to_err(f"service_error: {err}")
        if "result" in parsed_body:
            return res.to_ok(parsed_body["result"])
        return res.to_ok("unknown_response")
    except Exception as e:
        return res.to_err(e)


async def _ws_call(node: str, data: dict[str, object], timeout: float) -> Result[Any]:
    try:
        async with asyncio.timeout(timeout):
            async with websockets.connect(node) as ws:
                await ws.send(json.dumps(data))
                response = json.loads(await ws.recv())

        err = pydash.get(response, "error.message")
        if err:
            return Result.err(f"service_error: {err}", {"response": response})
        if "result" in response:
            return Result.ok(response["result"], {"response": response})
        return Result.err("unknown_response", {"response": response})
    except TimeoutError:
        return Result.err("timeout")
    except Exception as e:
        return Result.err(e)


# -- start eth rpc calls --


async def eth_block_number(node: str, timeout: float = TIMEOUT, proxy: str | None = None) -> Result[int]:
    return (await rpc_call(node, "eth_blockNumber", [], timeout, proxy)).map(_hex_str_to_int)


async def eth_get_balance(node: str, address: str, timeout: float = TIMEOUT, proxy: str | None = None) -> Result[int]:
    return (await rpc_call(node, "eth_getBalance", [address, "latest"], timeout, proxy)).map(_hex_str_to_int)


async def eth_chain_id(node: str, timeout: float = TIMEOUT, proxy: str | None = None) -> Result[int]:
    return (await rpc_call(node, "eth_chainId", [], timeout, proxy)).map(_hex_str_to_int)


async def eth_get_block_by_number(
    node: str, block_number: BlockIdentifier, full_transaction: bool = False, timeout: float = TIMEOUT, proxy: str | None = None
) -> Result[dict[str, Any]]:
    params = [hex(block_number) if isinstance(block_number, int) else block_number, full_transaction]
    return await rpc_call(node, "eth_getBlockByNumber", params, timeout, proxy)


# -- end eth rpc calls --

# -- start erc20 rpc calls --


async def erc20_balance(node: str, token: str, wallet: str, timeout: float = TIMEOUT, proxy: str | None = None) -> Result[int]:
    data = "0x70a08231000000000000000000000000" + wallet[2:]
    params = [{"to": token, "data": data}, "latest"]
    return (await rpc_call(node, "eth_call", params, timeout, proxy)).map(_hex_str_to_int)


async def erc20_name(node: str, token: str, timeout: float = TIMEOUT, proxy: str | None = None) -> Result[str]:
    params = [{"to": token, "data": "0x06fdde03"}, "latest"]
    return (await rpc_call(node, "eth_call", params, timeout, proxy)).map(_normalize_str)


async def erc20_symbol(node: str, token: str, timeout: float = TIMEOUT, proxy: str | None = None) -> Result[str]:
    params = [{"to": token, "data": "0x95d89b41"}, "latest"]
    return (await rpc_call(node, "eth_call", params, timeout, proxy)).map(_normalize_str)


async def erc20_decimals(node: str, token: str, timeout: float = TIMEOUT, proxy: str | None = None) -> Result[int]:
    params = [{"to": token, "data": "0x313ce567"}, "latest"]
    res = await rpc_call(node, "eth_call", params, timeout, proxy)
    if res.is_err():
        return res
    try:
        if res.unwrap() == "0x":
            return res.with_error("no_decimals")
        value = res.unwrap()
        result = eth_utils.to_int(hexstr=value[0:66]) if len(value) > 66 else eth_utils.to_int(hexstr=value)
        return res.with_value(result)
    except Exception as e:
        return res.with_error(e)


# -- end erc20 rpc calls --


async def ens_name(node: str, address: str, timeout: float = TIMEOUT, proxy: str | None = None) -> Result[str | None]:
    ens_registry_address: str = "0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e"
    func_selector_resolver: str = "0x0178b8bf"  # resolver(bytes32)
    func_selector_name: str = "0x691f3431"  # name(bytes32)

    checksum_addr = eth_utils.to_checksum_address(address)
    reverse_name = checksum_addr.lower()[2:] + ".addr.reverse"
    name_hash_hex = ens.utils.normal_name_to_hash(reverse_name).hex()

    resolver_data = func_selector_resolver + name_hash_hex

    resolver_params = [{"to": ens_registry_address, "data": resolver_data}, "latest"]

    resolver_res = await rpc_call(node, method="eth_call", params=resolver_params, timeout=timeout, proxy=proxy)
    if resolver_res.is_err():
        return resolver_res

    extra = {"resolver_response": resolver_res.to_dict()}

    if resolver_res.is_ok() and len(resolver_res.unwrap()) != 66:
        return Result.ok(None, extra)

    resolver_address = eth_utils.to_checksum_address("0x" + resolver_res.unwrap()[-40:])

    name_data: str = func_selector_name + name_hash_hex
    name_params = [{"to": resolver_address, "data": name_data}, "latest"]

    name_res = await rpc_call(node, "eth_call", name_params, timeout=timeout, proxy=proxy)

    extra["name_response"] = name_res.to_dict()

    if name_res.is_err():
        return Result.err(name_res.unwrap_error(), extra)

    if name_res.unwrap() == "0x":
        return Result.ok(None, extra)

    try:
        hex_data = name_res.unwrap()
        length_hex = hex_data[66:130]
        str_len = int(length_hex, 16) * 2
        name_hex = hex_data[130 : 130 + str_len]
        return Result.ok(bytes.fromhex(name_hex).decode("utf-8"), extra)
    except Exception as e:
        return Result.err(e, extra)


# -- start other --


async def get_base_fee_per_gas(node: str, timeout: float = TIMEOUT, proxy: str | None = None) -> Result[int]:
    res = await eth_get_block_by_number(node, "latest", False, timeout=timeout, proxy=proxy)
    if res.is_err():
        return Result.err(res.unwrap_error(), res.extra)
    if "baseFeePerGas" in res.unwrap():
        return res.with_value(int(res.unwrap()["baseFeePerGas"], 16))
    return Result.err("no_base_fee_per_gas", res.extra)


# -- end other --

# -- utils --


def _hex_str_to_int(value: str) -> int:
    return int(value, 16)


def _normalize_str(value: str) -> str:
    return "".join(filter(lambda x: x in string.printable, eth_utils.to_text(hexstr=value))).strip()
