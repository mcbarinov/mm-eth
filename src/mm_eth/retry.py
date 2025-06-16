from typing import Any, Literal

from eth_typing import BlockIdentifier
from mm_result import Result
from mm_web3 import Nodes, Proxies, retry_with_node_and_proxy
from web3.types import TxReceipt

from mm_eth import rpc

TIMEOUT = 5.0


# -- start eth rpc calls --


async def eth_block_number(retries: int, nodes: Nodes, proxies: Proxies, *, timeout: float = TIMEOUT) -> Result[int]:
    return await retry_with_node_and_proxy(
        retries, nodes, proxies, lambda node, proxy: rpc.eth_block_number(node, timeout, proxy)
    )


async def eth_get_balance(retries: int, nodes: Nodes, proxies: Proxies, *, address: str, timeout: float = TIMEOUT) -> Result[int]:
    return await retry_with_node_and_proxy(
        retries, nodes, proxies, lambda node, proxy: rpc.eth_get_balance(node, address, timeout, proxy)
    )


async def eth_chain_id(retries: int, nodes: Nodes, proxies: Proxies, *, timeout: float = TIMEOUT) -> Result[int]:
    return await retry_with_node_and_proxy(retries, nodes, proxies, lambda node, proxy: rpc.eth_chain_id(node, timeout, proxy))


async def eth_get_block_by_number(
    retries: int,
    nodes: Nodes,
    proxies: Proxies,
    *,
    block_number: BlockIdentifier,
    full_transaction: bool = False,
    timeout: float = TIMEOUT,
) -> Result[dict[str, Any]]:
    return await retry_with_node_and_proxy(
        retries,
        nodes,
        proxies,
        lambda node, proxy: rpc.eth_get_block_by_number(node, block_number, full_transaction, timeout, proxy),
    )


async def eth_get_transaction_count(
    retries: int, nodes: Nodes, proxies: Proxies, *, address: str, timeout: float = TIMEOUT
) -> Result[int]:
    return await retry_with_node_and_proxy(
        retries, nodes, proxies, lambda node, proxy: rpc.eth_get_transaction_count(node, address, timeout, proxy)
    )


async def eth_estimate_gas(
    retries: int,
    nodes: Nodes,
    proxies: Proxies,
    *,
    from_: str,
    to: str | None = None,
    value: int | None = 0,
    data: str | None = None,
    type_: Literal["0x0", "0x2"] | None = None,
    timeout: float = TIMEOUT,
) -> Result[int]:
    return await retry_with_node_and_proxy(
        retries, nodes, proxies, lambda node, proxy: rpc.eth_estimate_gas(node, from_, to, value, data, type_, timeout, proxy)
    )


async def eth_send_raw_transaction(
    retries: int, nodes: Nodes, proxies: Proxies, *, raw_tx: str, timeout: float = TIMEOUT
) -> Result[str]:
    return await retry_with_node_and_proxy(
        retries, nodes, proxies, lambda node, proxy: rpc.eth_send_raw_transaction(node, raw_tx, timeout, proxy)
    )


async def eth_get_transaction_receipt(
    retries: int, nodes: Nodes, proxies: Proxies, *, tx_hash: str, timeout: float = TIMEOUT
) -> Result[TxReceipt]:
    return await retry_with_node_and_proxy(
        retries, nodes, proxies, lambda node, proxy: rpc.eth_get_transaction_receipt(node, tx_hash, timeout, proxy)
    )


# -- end eth rpc calls --


# -- start erc20 rpc calls --


async def erc20_balance(
    retries: int, nodes: Nodes, proxies: Proxies, *, token: str, wallet: str, timeout: float = TIMEOUT
) -> Result[int]:
    return await retry_with_node_and_proxy(
        retries,
        nodes,
        proxies,
        lambda node, proxy: rpc.erc20_balance(node, token=token, wallet=wallet, proxy=proxy, timeout=timeout),
    )


async def erc20_name(retries: int, nodes: Nodes, proxies: Proxies, *, token: str, timeout: float = TIMEOUT) -> Result[str]:
    return await retry_with_node_and_proxy(
        retries, nodes, proxies, lambda node, proxy: rpc.erc20_name(node, token, timeout, proxy)
    )


async def erc20_symbol(retries: int, nodes: Nodes, proxies: Proxies, *, token: str, timeout: float = TIMEOUT) -> Result[str]:
    return await retry_with_node_and_proxy(
        retries, nodes, proxies, lambda node, proxy: rpc.erc20_symbol(node, token, timeout, proxy)
    )


async def erc20_decimals(retries: int, nodes: Nodes, proxies: Proxies, *, token: str, timeout: float = TIMEOUT) -> Result[int]:
    return await retry_with_node_and_proxy(
        retries, nodes, proxies, lambda node, proxy: rpc.erc20_decimals(node, token, timeout, proxy)
    )


# -- end erc20 rpc calls --

# -- start ens calls --


async def ens_name(retries: int, nodes: Nodes, proxies: Proxies, *, address: str, timeout: float = TIMEOUT) -> Result[str | None]:
    return await retry_with_node_and_proxy(
        retries, nodes, proxies, lambda node, proxy: rpc.ens_name(node, address, timeout, proxy)
    )


# -- stop ens calls --

# -- start other --


async def get_base_fee_per_gas(retries: int, nodes: Nodes, proxies: Proxies, *, timeout: float = TIMEOUT) -> Result[int]:
    return await retry_with_node_and_proxy(
        retries, nodes, proxies, lambda node, proxy: rpc.get_base_fee_per_gas(node, timeout, proxy)
    )


async def get_tx_status(retries: int, nodes: Nodes, proxies: Proxies, *, tx_hash: str, timeout: float = TIMEOUT) -> Result[int]:
    return await retry_with_node_and_proxy(
        retries, nodes, proxies, lambda node, proxy: rpc.get_tx_status(node, tx_hash, timeout, proxy)
    )


# -- end other --
