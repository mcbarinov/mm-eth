import asyncio
import json
import string
from collections.abc import Sequence
from typing import Any, Literal, cast

import ens.utils
import eth_utils
import pydash
import websockets
from eth_typing import BlockIdentifier
from mm_http import http_request
from mm_result import Result
from web3.types import TxReceipt

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
        return res.to_result_err()
    try:
        parsed_body = res.parse_json_body()
        err = parsed_body.get("error", {}).get("message", "")
        if err:
            return res.to_result_err(f"service_error: {err}")
        if "result" in parsed_body:
            return res.to_result_ok(parsed_body["result"])
        return res.to_result_err("unknown_response")
    except Exception as e:
        return res.to_result_err(e)


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


async def eth_get_transaction_count(node: str, address: str, timeout: float = TIMEOUT, proxy: str | None = None) -> Result[int]:
    return (await rpc_call(node, "eth_getTransactionCount", [address, "latest"], timeout, proxy)).map(_hex_str_to_int)


async def eth_estimate_gas(
    node: str,
    from_: str,
    to: str | None = None,
    value: int | None = 0,
    data: str | None = None,
    type_: Literal["0x0", "0x2"] | None = None,
    timeout: float = TIMEOUT,
    proxy: str | None = None,
) -> Result[int]:
    params: dict[str, Any] = {"from": from_}
    if to:
        params["to"] = to
    if data:
        params["data"] = data
    if value:
        params["value"] = hex(value)
    if type_:
        params["type"] = type_
    return (await rpc_call(node, "eth_estimateGas", [params], timeout, proxy)).map(_hex_str_to_int)


async def eth_send_raw_transaction(node: str, raw_tx: str, timeout: float = TIMEOUT, proxy: str | None = None) -> Result[str]:
    return await rpc_call(node, "eth_sendRawTransaction", [raw_tx], timeout, proxy)


async def eth_get_transaction_receipt(
    node: str, tx_hash: str, timeout: float = TIMEOUT, proxy: str | None = None
) -> Result[TxReceipt]:
    def convert_hex_str_ints(receipt: dict[str, Any]) -> TxReceipt:
        int_fields = {
            "blockNumber",
            "cumulativeGasUsed",
            "effectiveGasPrice",
            "gasUsed",
            "status",
            "transactionIndex",
            "type",
        }

        converted: dict[str, Any] = {}
        for key, value in receipt.items():
            if key in int_fields and isinstance(value, str) and value.startswith("0x"):
                converted[key] = int(value, 16)
            else:
                converted[key] = value

        return cast(TxReceipt, converted)

    res = await rpc_call(node, "eth_getTransactionReceipt", [tx_hash], timeout, proxy)
    if res.is_err():
        return res

    if res.unwrap() is None:
        return Result.err("no_receipt", res.extra)

    try:
        return Result.ok(convert_hex_str_ints(res.unwrap()), res.extra)
    except Exception as e:
        return Result.err(e, res.extra)


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

# -- start ens calls --


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
        return Result.err(name_res.unwrap_err(), extra)

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


# -- stop ens calls --

# -- start other --


async def get_base_fee_per_gas(node: str, timeout: float = TIMEOUT, proxy: str | None = None) -> Result[int]:
    res = await eth_get_block_by_number(node, "latest", False, timeout=timeout, proxy=proxy)
    if res.is_err():
        return Result.err(res.unwrap_err(), res.extra)
    if "baseFeePerGas" in res.unwrap():
        return res.with_value(int(res.unwrap()["baseFeePerGas"], 16))
    return Result.err("no_base_fee_per_gas", res.extra)


async def get_tx_status(node: str, tx_hash: str, timeout: float = TIMEOUT, proxy: str | None = None) -> Result[int]:
    res = await eth_get_transaction_receipt(node, tx_hash, timeout=timeout, proxy=proxy)
    if res.is_err():
        return Result.err(res.unwrap_err(), res.extra)
    status = res.unwrap().get("status")
    if status is None:
        return Result.err("no_status", res.extra)
    return Result.ok(status, res.extra)


# -- end other --

# -- utils --


def _hex_str_to_int(value: str) -> int:
    return int(value, 16)


def _normalize_str(value: str) -> str:
    return "".join(filter(lambda x: x in string.printable, eth_utils.to_text(hexstr=value))).strip()
