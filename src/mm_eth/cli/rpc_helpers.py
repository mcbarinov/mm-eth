import logging

from mm_web3 import Nodes, Proxies

from mm_eth import retry
from mm_eth.cli import calcs

logger = logging.getLogger(__name__)


async def get_nonce_with_logging(
    log_prefix: str | None, retries: int, nodes: Nodes, proxies: Proxies, *, address: str
) -> int | None:
    res = await retry.eth_get_transaction_count(retries, nodes, proxies, address=address)
    prefix = log_prefix or address
    if res.is_err():
        logger.error(f"{prefix}: nonce error: {res.unwrap_err()}")
        return None
    logger.debug(f"{prefix}: nonce={res.unwrap()}")
    return res.unwrap()


async def get_base_fee_with_logging(log_prefix: str | None, retries: int, nodes: Nodes, proxies: Proxies) -> int | None:
    prefix = get_log_prefix(log_prefix)
    res = await retry.get_base_fee_per_gas(retries, nodes, proxies)
    if res.is_err():
        logger.error(f"{prefix}base_fee error, {res.unwrap_err()}")
        return None

    logger.debug(f"{prefix}base_fee={res.unwrap()}")
    return res.unwrap()


async def calc_max_fee_with_logging(
    log_prefix: str | None, retries: int, nodes: Nodes, proxies: Proxies, *, max_fee_expression: str
) -> int | None:
    if "base_fee" in max_fee_expression.lower():
        base_fee = await get_base_fee_with_logging(log_prefix, retries, nodes, proxies)
        if base_fee is None:
            return None
        return calcs.calc_eth_expression(max_fee_expression, {"base_fee": base_fee})

    return calcs.calc_eth_expression(max_fee_expression)


def get_log_prefix(log_prefix: str | None) -> str:
    prefix = log_prefix or ""
    if prefix:
        prefix += ": "
    return prefix
