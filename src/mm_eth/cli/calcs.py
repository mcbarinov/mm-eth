import random
from decimal import Decimal

from mm_std.random_ import random_decimal
from mm_std.str import split_on_plus_minus_tokens

from mm_eth.utils import to_wei


def calc_var_wei_value(value: str, *, var_name: str = "var", var_value: int | None = None, decimals: int | None = None) -> int:
    if not isinstance(value, str):
        raise ValueError(f"value is not str: {value}")
    try:
        var_name = var_name.lower()
        result = 0
        for item in split_on_plus_minus_tokens(value.lower()):
            operator = item[0]
            item = item[1:]
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
                    raise ValueError("t without decimals")
                item = item.removesuffix("t")
                item_value = int(Decimal(item) * 10**decimals)
            elif item.endswith(var_name):
                if var_value is None:
                    raise ValueError("base value is not set")
                item = item.removesuffix(var_name)
                k = Decimal(item) if item else Decimal(1)
                item_value = int(k * var_value)
            elif item.startswith("random(") and item.endswith(")"):
                item = item.lstrip("random(").rstrip(")")
                arr = item.split(",")
                if len(arr) != 2:
                    raise ValueError(f"wrong value, random part: {value}")
                from_value = to_wei(arr[0], decimals=decimals)
                to_value = to_wei(arr[1], decimals=decimals)
                if from_value > to_value:
                    raise ValueError(f"wrong value, random part: {value}")
                item_value = random.randint(from_value, to_value)
            else:
                raise ValueError(f"wrong value: {value}")

            if operator == "+":
                result += item_value
            if operator == "-":
                result -= item_value

        return result
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
