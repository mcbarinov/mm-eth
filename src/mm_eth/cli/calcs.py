import random
from decimal import Decimal

from loguru import logger
from mm_std.random_ import random_decimal
from mm_std.str import split_on_plus_minus_tokens

from mm_eth.utils import from_wei_str, to_wei


def calc_var_wei_value(value: str, *, var_name: str = "var", var_value: int | None = None, decimals: int | None = None) -> int:
    if not isinstance(value, str):
        raise TypeError(f"value is not str: {value}")
    try:
        var_name = var_name.lower()
        result = 0
        for token in split_on_plus_minus_tokens(value.lower()):
            operator = token[0]
            item = token[1:]
            if item.isdigit():
                item_value = int(item)
            elif item.endswith("eth"):
                item = item.removesuffix("eth")
                item_value = int(Decimal(item) * 10**18)
            elif item.endswith("ether"):
                item = item.removesuffix("ether")
                item_value = int(Decimal(item) * 10**18)
            elif item.endswith("gwei"):
                item = item.removesuffix("gwei")
                item_value = int(Decimal(item) * 10**9)
            elif item.endswith("t"):
                if decimals is None:
                    raise ValueError("t without decimals")  # noqa: TRY301
                item = item.removesuffix("t")
                item_value = int(Decimal(item) * 10**decimals)
            elif item.endswith(var_name):
                if var_value is None:
                    raise ValueError("base value is not set")  # noqa: TRY301
                item = item.removesuffix(var_name)
                k = Decimal(item) if item else Decimal(1)
                item_value = int(k * var_value)
            elif item.startswith("random(") and item.endswith(")"):
                item = item.lstrip("random(").rstrip(")")
                arr = item.split(",")
                if len(arr) != 2:
                    raise ValueError(f"wrong value, random part: {value}")  # noqa: TRY301
                from_value = to_wei(arr[0], decimals=decimals)
                to_value = to_wei(arr[1], decimals=decimals)
                if from_value > to_value:
                    raise ValueError(f"wrong value, random part: {value}")  # noqa: TRY301
                item_value = random.randint(from_value, to_value)
            else:
                raise ValueError(f"wrong value: {value}")  # noqa: TRY301

            if operator == "+":
                result += item_value
            if operator == "-":
                result -= item_value

        return result  # noqa: TRY300
    except Exception as err:
        raise ValueError(f"wrong value: {value}, error={err}") from err


def calc_decimal_value(value: str) -> Decimal:
    value = value.lower().strip()
    if value.startswith("random(") and value.endswith(")"):
        arr = value.lstrip("random(").rstrip(")").split(",")
        if len(arr) != 2:
            raise ValueError(f"wrong value, random part: {value}")
        from_value = Decimal(arr[0])
        to_value = Decimal(arr[1])
        if from_value > to_value:
            raise ValueError(f"wrong value, random part: {value}")
        return random_decimal(from_value, to_value)
    return Decimal(value)


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


def is_value_less_min_limit(
    value_min_limit: str | None,
    value: int,
    value_unit: str,
    decimals: int | None = None,
    log_prefix: str | None = None,
) -> bool:
    if value_min_limit is None:
        return False
    if value < calc_var_wei_value(value_min_limit, decimals=decimals):
        prefix = _get_prefix(log_prefix)
        logger.info("{}value is less min limit, value={}", prefix, from_wei_str(value, value_unit, decimals=decimals))
        return True
    return False


def _get_prefix(log_prefix: str | None) -> str:
    prefix = log_prefix or ""
    if prefix:
        prefix += ": "
    return prefix
