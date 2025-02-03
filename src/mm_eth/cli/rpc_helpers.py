import mm_crypto_utils
from loguru import logger
from mm_crypto_utils import VarInt, get_log_prefix
from mm_std import Err, fatal

from mm_eth import erc20, rpc
from mm_eth.utils import from_wei_str

from .calcs import calc_eth_expression


def get_nonce(nodes: list[str] | str, address: str, log_prefix: str | None = None) -> int | None:
    res = rpc.eth_get_transaction_count(nodes, address, attempts=5)
    prefix = log_prefix or address
    logger.debug(f"{prefix}: nonce={res.ok_or_err()}")
    if isinstance(res, Err):
        logger.info(f"{prefix}: nonce error, {res.err}")
        return None
    return res.ok


def check_nodes_for_chain_id(nodes: list[str], chain_id: int) -> None:
    for node in nodes:
        res = rpc.eth_chain_id(node, timeout=7)
        if isinstance(res, Err):
            fatal(f"can't get chain_id for {node}, error={res.err}")
        if res.ok != chain_id:
            fatal(f"node {node} has a wrong chain_id: {res.ok}")


def get_base_fee(nodes: list[str], log_prefix: str | None = None) -> int | None:
    res = rpc.get_base_fee_per_gas(nodes)
    prefix = get_log_prefix(log_prefix)
    logger.debug(f"{prefix}base_fee={res.ok_or_err()}")
    if isinstance(res, Err):
        logger.info(f"{prefix}base_fee error, {res.err}")
        return None
    return res.ok


def calc_max_fee(nodes: list[str], max_fee_expression: str, log_prefix: str | None = None) -> int | None:
    if "base_fee" in max_fee_expression.lower():
        base_fee = get_base_fee(nodes, log_prefix)
        if base_fee is None:
            return None
        return calc_eth_expression(max_fee_expression, VarInt("base_fee", base_fee))

    return calc_eth_expression(max_fee_expression)


def is_max_fee_limit_exceeded(max_fee: int, max_fee_limit_expression: str | None, log_prefix: str | None = None) -> bool:
    if max_fee_limit_expression is None:
        return False
    max_limit_value = calc_eth_expression(max_fee_limit_expression)
    if max_fee > max_limit_value:
        prefix = get_log_prefix(log_prefix)
        logger.info(
            "{}max_fee_limit is exceeded, max_fee={}, max_fee_limit={}",
            prefix,
            from_wei_str(max_fee, "gwei"),
            from_wei_str(max_limit_value, "gwei"),
        )
        return True
    return False


def calc_gas(
    *,
    nodes: list[str],
    gas_expression: str,
    from_address: str,
    to_address: str,
    value: int | None = None,
    data: str | None = None,
    log_prefix: str | None = None,
) -> int | None:
    var = None
    if "estimate" in gas_expression.lower():
        prefix = get_log_prefix(log_prefix)
        res = rpc.eth_estimate_gas(nodes, from_address, to_address, data=data, value=value, attempts=5)
        logger.debug(f"{prefix}gas_estimate={res.ok_or_err()}")
        if isinstance(res, Err):
            logger.info(f"{prefix}estimate_gas error, {res.err}")
            return None
        var = VarInt("estimate", res.ok)
    return calc_eth_expression(gas_expression, var)


def calc_eth_value_for_address(
    *,
    nodes: list[str],
    value_expression: str,
    address: str,
    gas: int,
    max_fee: int,
    log_prefix: str | None = None,
) -> int | None:
    var = None
    if "balance" in value_expression.lower():
        prefix = get_log_prefix(log_prefix)
        res = rpc.eth_get_balance(nodes, address, attempts=5)
        logger.debug(f"{prefix}balance={res.ok_or_err()}")
        if isinstance(res, Err):
            logger.info(f"{prefix}balance error, {res.err}")
            return None
        var = VarInt("balance", res.ok)

    value = calc_eth_expression(value_expression, var)
    if "balance" in value_expression.lower():
        value = value - gas * max_fee
    return value


def calc_erc20_value_for_address(
    *,
    nodes: list[str],
    value_expression: str,
    wallet_address: str,
    token_address: str,
    decimals: int,
    log_prefix: str | None = None,
) -> int | None:
    value_expression = value_expression.lower()
    var = None
    if "balance" in value_expression:
        prefix = get_log_prefix(log_prefix)
        res = erc20.get_balance(nodes, token_address, wallet_address, attempts=5)
        logger.debug(f"{prefix}balance={res.ok_or_err()}")
        if isinstance(res, Err):
            logger.info(f"{prefix}balance error, {res.err}")
            return None
        var = VarInt("balance", res.ok)
    return mm_crypto_utils.calc_int_expression(value_expression, var, suffix_decimals={"t": decimals})
