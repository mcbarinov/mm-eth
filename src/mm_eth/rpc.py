from __future__ import annotations

import json
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Literal, cast

import websocket
from mm_std import Err, Ok, Result, hr, random_choice
from pydantic import BaseModel

from mm_eth.utils import hex_str_to_int, random_node, random_proxy

if TYPE_CHECKING:
    from web3.types import BlockIdentifier

    from mm_eth.types import Nodes, Proxies


@dataclass
class TxReceipt:
    tx_hash: str
    tx_index: int
    block_number: int
    from_address: str
    to_address: str | None
    contract_address: str | None
    status: int | None


@dataclass
class Log:
    address: str
    block_hash: str
    block_number: int
    data: str
    log_index: int
    removed: bool
    topics: list[str]
    transaction_hash: str
    transaction_index: int

    @classmethod
    def from_json_rpc_dict(cls, data: dict[str, Any]) -> Result[Log]:
        try:
            return Ok(
                Log(
                    address=data["address"],
                    block_hash=data["blockHash"],
                    block_number=int(data["blockNumber"], 16),
                    data=data["data"],
                    log_index=int(data["logIndex"], 16),
                    removed=data["removed"],
                    topics=data["topics"],
                    transaction_hash=data["transactionHash"],
                    transaction_index=int(data["transactionIndex"], 16),
                ),
            )
        except Exception as err:
            return Err(f"exception: {err}")


class TxData(BaseModel):
    block_number: int | None  # for pending tx it can be none
    from_: str
    to: str | None
    gas: int
    gas_price: int
    value: int
    hash: str
    input: str
    nonce: int
    v: int
    r: str
    s: str


def rpc_call(
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
        res = _http_call(node, data, timeout, random_proxy(proxies)) if node.startswith("http") else _ws_call(node, data, timeout)
        if isinstance(res, Ok):
            return res
    return res


def _http_call(node: str, data: dict[str, object], timeout: int, proxy: str | None) -> Result[Any]:
    res = hr(node, method="POST", proxy=proxy, timeout=timeout, params=data, json_params=True)
    try:
        if res.is_error():
            return res.to_err_result()

        err = res.json.get("error", {}).get("message", "")
        if err:
            return res.to_err_result(f"service_error: {err}")
        if "result" in res.json:
            return res.to_ok_result(res.json["result"])

        return res.to_err_result("unknown_response")
    except Exception as err:
        return res.to_err_result(f"exception: {err}")


def _ws_call(node: str, data: dict[str, object], timeout: int) -> Result[Any]:
    try:
        ws = websocket.create_connection(node, timeout=timeout)
        ws.send(json.dumps(data))
        response = json.loads(ws.recv())
        ws.close()
        err = response.get("error", {}).get("message", "")
        if err:
            return Err(f"service_error: {err}")
        if "result" in response:
            return Ok(response["result"])
        return Err(f"unknown_response: {response}")
    except TimeoutError:
        return Err("timeout")
    except Exception as err:
        return Err(f"exception: {err}")


def eth_block_number(rpc_urls: Nodes, timeout: int = 10, proxies: Proxies = None, attempts: int = 1) -> Result[int]:
    return rpc_call(
        nodes=rpc_urls,
        method="eth_blockNumber",
        params=[],
        timeout=timeout,
        proxies=proxies,
        attempts=attempts,
    ).and_then(hex_str_to_int)


def eth_chain_id(rpc_urls: Nodes, timeout: int = 10, proxies: Proxies = None, attempts: int = 1) -> Result[int]:
    return rpc_call(
        nodes=rpc_urls,
        method="eth_chainId",
        params=[],
        timeout=timeout,
        proxies=proxies,
        attempts=attempts,
    ).and_then(hex_str_to_int)


def net_peer_count(rpc_urls: Nodes, timeout: int = 10, proxies: Proxies = None, attempts: int = 1) -> Result[int]:
    return rpc_call(
        nodes=rpc_urls,
        method="net_peerCount",
        params=[],
        timeout=timeout,
        proxies=proxies,
        attempts=attempts,
    ).and_then(hex_str_to_int)


def web3_client_version(rpc_urls: Nodes, timeout: int = 10, proxies: Proxies = None, attempts: int = 1) -> Result[str]:
    return rpc_call(
        nodes=rpc_urls,
        method="web3_clientVersion",
        params=[],
        timeout=timeout,
        proxies=proxies,
        attempts=attempts,
    )


def net_version(nodes: Nodes, timeout: int = 10, proxies: Proxies = None, attempts: int = 1) -> Result[str]:
    return rpc_call(nodes=nodes, method="net_version", params=[], timeout=timeout, proxies=proxies, attempts=attempts)


def eth_get_code(rpc_urls: Nodes, address: str, timeout: int = 10, proxies: Proxies = None, attempts: int = 1) -> Result[str]:
    return rpc_call(
        nodes=rpc_urls,
        method="eth_getCode",
        params=[address, "latest"],
        timeout=timeout,
        proxies=proxies,
        attempts=attempts,
    )


def eth_send_raw_transaction(
    rpc_urls: Nodes,
    raw_tx: str,
    timeout: int = 10,
    proxies: Proxies = None,
    attempts: int = 1,
) -> Result[str]:
    return rpc_call(
        nodes=rpc_urls,
        method="eth_sendRawTransaction",
        params=[raw_tx],
        timeout=timeout,
        proxies=proxies,
        attempts=attempts,
    )


def eth_get_balance(rpc_urls: Nodes, address: str, timeout: int = 10, proxies: Proxies = None, attempts: int = 1) -> Result[int]:
    return rpc_call(
        nodes=rpc_urls,
        method="eth_getBalance",
        params=[address, "latest"],
        timeout=timeout,
        proxies=proxies,
        attempts=attempts,
    ).and_then(hex_str_to_int)


def eth_get_transaction_count(
    rpc_urls: Nodes,
    address: str,
    timeout: int = 10,
    proxies: Proxies = None,
    attempts: int = 1,
) -> Result[int]:
    return rpc_call(
        nodes=rpc_urls,
        method="eth_getTransactionCount",
        params=[address, "latest"],
        timeout=timeout,
        proxies=proxies,
        attempts=attempts,
    ).and_then(hex_str_to_int)


def eth_get_block_by_number(
    rpc_urls: Nodes,
    block_number: BlockIdentifier,
    full_transaction: bool = False,
    timeout: int = 10,
    proxies: Proxies = None,
    attempts: int = 1,
) -> Result[dict[str, Any]]:
    return rpc_call(
        nodes=rpc_urls,
        method="eth_getBlockByNumber",
        params=[hex(block_number) if isinstance(block_number, int) else block_number, full_transaction],
        timeout=timeout,
        proxies=proxies,
        attempts=attempts,
    )


def eth_get_logs(
    rpc_urls: Nodes,
    *,
    address: str | None = None,
    topics: list[str] | None = None,
    from_block: BlockIdentifier | None = None,
    to_block: BlockIdentifier | None = None,
    timeout: int = 10,
    proxies: Proxies = None,
    attempts: int = 1,
) -> Result[list[Log]]:
    params: dict[str, object] = {}
    if address:
        params["address"] = address
    if isinstance(from_block, int):
        params["fromBlock"] = hex(from_block)
    else:
        params["fromBlock"] = "earliest"
    if isinstance(to_block, int):
        params["toBlock"] = hex(to_block)
    if topics:
        params["topics"] = topics

    res = rpc_call(nodes=rpc_urls, method="eth_getLogs", params=[params], proxies=proxies, attempts=attempts, timeout=timeout)
    if isinstance(res, Err):
        return res

    result: list[Log] = []
    for log_data in res.ok:
        log_res = Log.from_json_rpc_dict(log_data)
        if isinstance(log_res, Err):
            return Err(log_res.err, data=res.data)
        result.append(log_res.ok)
    return Ok(result, data=res.data)


def eth_get_transaction_receipt(
    rpc_urls: Nodes,
    tx_hash: str,
    timeout: int = 10,
    proxies: Proxies = None,
    attempts: int = 1,
) -> Result[TxReceipt]:
    res = rpc_call(
        nodes=rpc_urls,
        method="eth_getTransactionReceipt",
        params=[tx_hash],
        timeout=timeout,
        proxies=proxies,
        attempts=attempts,
    )
    if isinstance(res, Err):
        return res

    if res.ok is None:
        return Err("no_receipt", data=res.data)

    try:
        status = None
        receipt = cast(dict[str, Any], res.ok)
        if "status" in receipt:
            status = int(receipt["status"], 16)
        return Ok(
            TxReceipt(
                tx_hash=tx_hash,
                tx_index=int(receipt["transactionIndex"], 16),
                block_number=int(receipt["blockNumber"], 16),
                from_address=receipt["from"],
                to_address=receipt.get("to"),
                contract_address=receipt.get("contractAddress"),
                status=status,
            ),
            data=res.data,
        )
    except Exception as err:
        return Err(f"exception: {err}", data=res.data)


def eth_get_transaction_by_hash(
    rpc_urls: Nodes,
    tx_hash: str,
    timeout: int = 10,
    proxies: Proxies = None,
    attempts: int = 1,
) -> Result[TxData]:
    res = rpc_call(
        nodes=rpc_urls,
        method="eth_getTransactionByHash",
        params=[tx_hash],
        timeout=timeout,
        proxies=proxies,
        attempts=attempts,
    )
    if isinstance(res, Err):
        return res
    if res.ok is None:
        return Err("not_found", data=res.data)

    try:
        tx = res.ok
        return Ok(
            TxData(
                block_number=int(tx["blockNumber"], 16) if tx["blockNumber"] is not None else None,
                from_=tx["from"],
                to=tx.get("to"),
                gas=int(tx["gas"], 16),
                gas_price=int(tx["gasPrice"], 16),
                value=int(tx["value"], 16),
                nonce=int(tx["nonce"], 16),
                input=tx["input"],
                hash=tx_hash,
                v=int(tx["v"], 16),
                r=tx.get("r"),
                s=tx.get("s"),
            ),
            data=res.data,
        )

    except Exception as err:
        return Err(f"exception: {err}", data=res.data)


def eth_call(
    rpc_urls: Nodes,
    to: str,
    data: str,
    timeout: int = 10,
    proxies: Proxies = None,
    attempts: int = 1,
) -> Result[str]:
    return rpc_call(
        nodes=rpc_urls,
        method="eth_call",
        params=[{"to": to, "data": data}, "latest"],
        timeout=timeout,
        proxies=proxies,
        attempts=attempts,
    )


def eth_estimate_gas(
    rpc_urls: Nodes,
    from_: str,
    to: str | None = None,
    value: int | None = 0,
    data: str | None = None,
    type_: Literal["0x0", "0x2"] | None = None,
    timeout: int = 10,
    proxies: Proxies = None,
    attempts: int = 1,
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
    return rpc_call(
        nodes=rpc_urls,
        method="eth_estimateGas",
        params=[params],
        timeout=timeout,
        proxies=proxies,
        attempts=attempts,
    ).and_then(hex_str_to_int)


def eth_gas_price(rpc_urls: Nodes, timeout: int = 10, proxies: Proxies = None, attempts: int = 1) -> Result[int]:
    return rpc_call(
        nodes=rpc_urls,
        method="eth_gasPrice",
        params=[],
        timeout=timeout,
        proxies=proxies,
        attempts=attempts,
    ).and_then(hex_str_to_int)


def eth_syncing(rpc_urls: Nodes, timeout: int = 10, proxies: Proxies = None, attempts: int = 1) -> Result[bool | dict[str, int]]:
    res = rpc_call(nodes=rpc_urls, method="eth_syncing", params=[], timeout=timeout, proxies=proxies, attempts=attempts)
    if isinstance(res, Err):
        return res

    if isinstance(res.ok, dict):
        result = {}
        for k, v in res.ok.items():
            if v:
                result[k] = int(v, 16)
            else:
                result[k] = v
        if result.get("currentBlock") and result.get("highestBlock"):
            result["remaining"] = result["highestBlock"] - result["currentBlock"]
        return Ok(result, res.data)

    return res


def get_tx_status(rpc_urls: Nodes, tx_hash: str, timeout: int = 5, proxies: Proxies = None, attempts: int = 5) -> Result[int]:
    res: Result[int] = Err("not started yet")
    for _ in range(attempts):
        node = cast(str, random_choice(rpc_urls))
        cast(str | None, random_choice(proxies))
        receipt_res = eth_get_transaction_receipt(node, tx_hash, timeout, proxies=proxies, attempts=1)
        if isinstance(receipt_res, Err) and receipt_res.err == "no_receipt":
            return receipt_res
        if isinstance(receipt_res, Ok) and receipt_res.ok.status is None:
            return Err("no_status", data=res.data)

        if isinstance(receipt_res, Ok):
            return Ok(cast(int, receipt_res.ok.status), data=receipt_res.data)
        res = receipt_res

    return res


def get_base_fee_per_gas(rpc_urls: Nodes, timeout: int = 5, proxies: Proxies = None, attempts: int = 5) -> Result[int]:
    res = eth_get_block_by_number(rpc_urls, "latest", False, timeout=timeout, proxies=proxies, attempts=attempts)
    if isinstance(res, Err):
        return res
    if "baseFeePerGas" in res.ok:
        return Ok(int(res.ok["baseFeePerGas"], 16), data=res.data)
    return Err("no_base_fee_per_gas", data=res.data)
