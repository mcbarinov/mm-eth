from loguru import logger
from mm_std import Err, fatal

from mm_eth import erc20, rpc
from mm_eth.utils import from_wei_str

from . import calcs


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
    prefix = _get_prefix(log_prefix)
    logger.debug(f"{prefix}base_fee={res.ok_or_err()}")
    if isinstance(res, Err):
        logger.info(f"{prefix}base_fee error, {res.err}")
        return None
    return res.ok


def calc_max_fee_per_gas(nodes: list[str], max_fee_per_gas: str, log_prefix: str | None = None) -> int | None:
    if "base" in max_fee_per_gas.lower():
        base_fee = get_base_fee(nodes, log_prefix)
        if base_fee is None:
            return None
        return calcs.calc_var_wei_value(max_fee_per_gas, var_name="base", var_value=base_fee)
    return calcs.calc_var_wei_value(max_fee_per_gas)


def is_max_fee_per_gas_limit_exceeded(
    max_fee_per_gas: int,
    max_fee_per_gas_limit: str | None,
    log_prefix: str | None = None,
) -> bool:
    if max_fee_per_gas_limit is None:
        return False
    max_fee_per_gas_limit_value = calcs.calc_var_wei_value(max_fee_per_gas_limit)
    if max_fee_per_gas > max_fee_per_gas_limit_value:
        prefix = _get_prefix(log_prefix)
        logger.info(
            "{}max_fee_per_gas_limit is exeeded, max_fee_per_gas={}, max_fee_per_gas_limit={}",
            prefix,
            from_wei_str(max_fee_per_gas, "gwei"),
            from_wei_str(max_fee_per_gas_limit_value, "gwei"),
        )
        return True
    return False


def calc_gas(
    *,
    nodes: list[str],
    gas: str,
    from_address: str,
    to_address: str,
    value: int | None = None,
    data: str | None = None,
    log_prefix: str | None = None,
) -> int | None:
    estimate_value = None
    if "estimate" in gas.lower():
        prefix = _get_prefix(log_prefix)
        res = rpc.eth_estimate_gas(nodes, from_address, to_address, data=data, value=value, attempts=5)
        logger.debug(f"{prefix}gas_estimate={res.ok_or_err()}")
        if isinstance(res, Err):
            logger.info(f"{prefix}estimate_gas error, {res.err}")
            return None
        estimate_value = res.ok
    return calcs.calc_var_wei_value(gas, var_name="estimate", var_value=estimate_value)


def calc_eth_value(
    *,
    nodes: list[str],
    value_str: str,
    address: str,
    gas: int | None = None,
    max_fee_per_gas: int | None = None,
    log_prefix: str | None = None,
) -> int | None:
    balance_value = None
    if "balance" in value_str.lower():
        prefix = _get_prefix(log_prefix)
        res = rpc.eth_get_balance(nodes, address, attempts=5)
        logger.debug(f"{prefix}balance={res.ok_or_err()}")
        if isinstance(res, Err):
            logger.info(f"{prefix}balance error, {res.err}")
            return None
        balance_value = res.ok
    value = calcs.calc_var_wei_value(value_str, var_name="balance", var_value=balance_value)
    if "balance" in value_str.lower() and gas is not None and max_fee_per_gas is not None:
        value = value - gas * max_fee_per_gas
    return value


def calc_erc20_value(
    *,
    nodes: list[str],
    value_str: str,
    wallet_address: str,
    token_address: str,
    decimals: int,
    log_prefix: str | None = None,
) -> int | None:
    value_str = value_str.lower()
    balance_value = None
    if "balance" in value_str:
        prefix = _get_prefix(log_prefix)
        res = erc20.get_balance(nodes, token_address, wallet_address, attempts=5)
        logger.debug(f"{prefix}balance={res.ok_or_err()}")
        if isinstance(res, Err):
            logger.info(f"{prefix}balance error, {res.err}")
            return None
        balance_value = res.ok
    return calcs.calc_var_wei_value(value_str, var_name="balance", var_value=balance_value, decimals=decimals)


def _get_prefix(log_prefix: str | None) -> str:
    prefix = log_prefix or ""
    if prefix:
        prefix += ": "
    return prefix
