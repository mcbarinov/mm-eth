import mm_crypto_utils
from mm_crypto_utils import VarInt

from mm_eth.cli.validators import SUFFIX_DECIMALS


def calc_eth_expression(expression: str, var: VarInt | None = None) -> int:
    return mm_crypto_utils.calc_int_expression(expression, var=var, suffix_decimals=SUFFIX_DECIMALS)


def calc_token_expression(expression: str, token_decimals: int, var: VarInt | None = None) -> int:
    return mm_crypto_utils.calc_int_expression(expression, var=var, suffix_decimals={"t": token_decimals})
