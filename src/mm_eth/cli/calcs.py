import random

import mm_crypto_utils
from mm_crypto_utils import VarInt

from mm_eth.constants import SUFFIX_DECIMALS


def calc_eth_expression(expression: str, var: VarInt | None = None) -> int:
    return mm_crypto_utils.calc_int_expression(expression, var=var, suffix_decimals=SUFFIX_DECIMALS)


def calc_token_expression(expression: str, token_decimals: int, var: VarInt | None = None) -> int:
    return mm_crypto_utils.calc_int_expression(expression, var=var, suffix_decimals={"t": token_decimals})


def calc_function_args(value: str) -> str:
    while True:
        if "random(" not in value:
            return value
        start_index = value.index("random(")
        stop_index = value.index(")", start_index)
        random_range = [int(v.strip()) for v in value[start_index + 7 : stop_index].split(",")]
        if len(random_range) != 2:
            raise ValueError("wrong random(from,to) template")
        rand_value = str(random.randint(random_range[0], random_range[1]))
        value = value[0:start_index] + rand_value + value[stop_index + 1 :]
