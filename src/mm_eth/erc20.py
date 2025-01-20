from __future__ import annotations

import string
from dataclasses import dataclass
from typing import TYPE_CHECKING

import eth_abi
import eth_utils
from eth_typing import HexStr
from eth_utils import to_checksum_address, to_hex
from mm_std import Err, Ok, Result

from mm_eth import rpc
from mm_eth.tx import SignedTx, sign_legacy_tx, sign_tx
from mm_eth.utils import hex_str_to_int, hex_to_bytes, log_topic_to_address

if TYPE_CHECKING:
    from collections.abc import Sequence

    from mm_eth.rpc import Log
    from mm_eth.types import Nodes, Proxies

TRANSFER_METHOD = "0xa9059cbb"
TRANSFER_TOPIC = HexStr("0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef")


USDT_MAINNET_ADDRESS = "0xdac17f958d2ee523a2206206994597c13d831ec7"


@dataclass
class TransferEventLog:
    token_address: str
    from_address: str
    to_address: str
    value: int
    tx_hash: str
    block_number: int
    log_index: int

    @staticmethod
    def from_log(log: Log) -> Result[TransferEventLog]:
        try:
            return Ok(
                TransferEventLog(
                    token_address=log.address,
                    from_address=log_topic_to_address(log.topics[1]),
                    to_address=log_topic_to_address(log.topics[2]),
                    value=int(log.data, 16),
                    tx_hash=log.transaction_hash,
                    block_number=log.block_number,
                    log_index=log.log_index,
                ),
            )
        except Exception as err:
            return Err(err)


def get_balance(
    rpc_urls: Nodes,
    token_address: str,
    user_address: str,
    timeout: int = 10,
    proxies: Proxies = None,
    attempts: int = 1,
) -> Result[int]:
    data = "0x70a08231000000000000000000000000" + user_address[2:]
    return rpc.rpc_call(
        nodes=rpc_urls,
        method="eth_call",
        params=[{"to": token_address, "data": data}, "latest"],
        timeout=timeout,
        proxies=proxies,
        attempts=attempts,
    ).and_then(hex_str_to_int)


def get_name(rpc_urls: Nodes, address: str, timeout: int = 10, proxies: Proxies = None, attempts: int = 1) -> Result[str]:
    return rpc.rpc_call(
        nodes=rpc_urls,
        method="eth_call",
        params=[{"to": address, "data": "0x06fdde03"}, "latest"],
        timeout=timeout,
        proxies=proxies,
        attempts=attempts,
    ).and_then(_normalize_str)


def get_symbol(rpc_urls: Nodes, address: str, timeout: int = 10, proxies: Proxies = None, attempts: int = 1) -> Result[str]:
    return rpc.rpc_call(
        nodes=rpc_urls,
        method="eth_call",
        params=[{"to": address, "data": "0x95d89b41"}, "latest"],
        timeout=timeout,
        proxies=proxies,
        attempts=attempts,
    ).and_then(_normalize_str)


def get_decimals(rpc_urls: Nodes, address: str, timeout: int = 10, proxies: Proxies = None, attempts: int = 1) -> Result[int]:
    res = rpc.rpc_call(
        nodes=rpc_urls,
        method="eth_call",
        params=[{"to": address, "data": "0x313ce567"}, "latest"],
        timeout=timeout,
        proxies=proxies,
        attempts=attempts,
    )
    if isinstance(res, Err):
        return res

    try:
        if res.ok == "0x":
            return Err("no_decimals", data=res.data)

        result = eth_utils.to_int(hexstr=res.ok[0:66]) if len(res.ok) > 66 else eth_utils.to_int(hexstr=res.ok)
        return Ok(result, data=res.data)

    except Exception as e:
        return Err(f"exception: {e}", data=res.data)


def encode_transfer_input_data(recipient: str, value: int) -> str:
    recipient = to_checksum_address(recipient)
    input_data = hex_to_bytes(TRANSFER_METHOD) + eth_abi.encode(["address", "uint256"], [recipient, value])
    return to_hex(input_data)


def transfer_token_legacy(
    *,
    rpc_urls: str | Sequence[str],
    token_address: str,
    recipient_address: str,
    value: int,
    nonce: int,
    gas_price: int,
    gas_limit: int,
    private_key: str,
    chain_id: int,
    timeout: int = 10,
    proxies: Proxies = None,
    attempts: int = 1,
) -> Result[str]:
    input_data = encode_transfer_input_data(recipient_address, value)
    signed_tx = sign_legacy_tx(
        nonce=nonce,
        gas_price=gas_price,
        gas=gas_limit,
        private_key=private_key,
        chain_id=chain_id,
        data=input_data,
        to=token_address,
    )
    return rpc.eth_send_raw_transaction(rpc_urls, signed_tx.raw_tx, timeout=timeout, proxies=proxies, attempts=attempts)


def transfer_token(
    *,
    rpc_urls: Nodes,
    token_address: str,
    recipient_address: str,
    value: int,
    nonce: int,
    max_fee_per_gas: int,
    max_priority_fee_per_gas: int,
    gas_limit: int,
    private_key: str,
    chain_id: int,
    timeout: int = 10,
    proxies: Proxies = None,
    attempts: int = 1,
) -> Result[str]:
    input_data = encode_transfer_input_data(recipient_address, value)
    signed_tx = sign_tx(
        nonce=nonce,
        max_fee_per_gas=max_fee_per_gas,
        max_priority_fee_per_gas=max_priority_fee_per_gas,
        gas=gas_limit,
        private_key=private_key,
        chain_id=chain_id,
        data=input_data,
        to=token_address,
    )
    return rpc.eth_send_raw_transaction(rpc_urls, signed_tx.raw_tx, timeout=timeout, proxies=proxies, attempts=attempts)


def sign_transfer_tx(
    *,
    token_address: str,
    recipient_address: str,
    value: int,
    nonce: int,
    max_fee_per_gas: int,
    max_priority_fee_per_gas: int,
    gas_limit: int,
    private_key: str,
    chain_id: int,
) -> SignedTx:
    input_data = encode_transfer_input_data(recipient_address, value)
    return sign_tx(
        nonce=nonce,
        max_fee_per_gas=max_fee_per_gas,
        max_priority_fee_per_gas=max_priority_fee_per_gas,
        gas=gas_limit,
        private_key=private_key,
        chain_id=chain_id,
        data=input_data,
        to=token_address,
    )


def get_transfer_event_logs(
    rpc_urls: Nodes,
    token_address: str | None,
    from_block: int,
    to_block: int,
    timeout: int = 10,
    proxies: Proxies = None,
    attempts: int = 1,
) -> Result[list[TransferEventLog]]:
    res = rpc.eth_get_logs(
        rpc_urls,
        address=token_address,
        topics=[TRANSFER_TOPIC],
        from_block=from_block,
        to_block=to_block,
        timeout=timeout,
        proxies=proxies,
        attempts=attempts,
    )
    if isinstance(res, Err):
        return res
    result: list[TransferEventLog] = []
    for log in res.ok:
        event_log_res = TransferEventLog.from_log(log)
        if isinstance(event_log_res, Ok):
            result.append(event_log_res.ok)
    return Ok(result, data=res.data)


def _normalize_str(value: str) -> Ok[str]:
    return Ok("".join(filter(lambda x: x in string.printable, eth_utils.to_text(hexstr=value))).strip())
