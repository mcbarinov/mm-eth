import os
from decimal import Decimal, InvalidOperation
from pathlib import Path

from mm_std import str_to_list

from mm_eth.utils import to_wei

from . import calcs


def wei_validator(v: str | None) -> int | None:
    if v is None:
        return None
    return to_wei(v)


def log_validator(v: str | None) -> str | None:
    if v is None:
        return None
    log_file = Path(v).expanduser()
    log_file.touch(exist_ok=True)
    if not (log_file.is_file() and os.access(log_file, os.W_OK)):
        raise ValueError(f"wrong log path: {v}")
    return v


def nodes_validator(v: str | list[str] | None) -> list[str]:
    if v is None:
        return []
    if isinstance(v, str):
        return str_to_list(v, unique=True, remove_comments=True, split_line=True)
    return v


def addresses_validator(v: str | list[str] | None) -> list[str]:
    if v is None:
        return []
    if isinstance(v, str):
        return str_to_list(v, unique=True, remove_comments=True, split_line=True, lower=True)
    return v


def delay_validator(v: str | Decimal) -> Decimal | tuple[Decimal, Decimal]:
    if isinstance(v, int | float):
        return Decimal(str(v))
    if isinstance(v, str):
        arr = [a.strip() for a in v.split("-")]
        if len(arr) != 2:
            raise ValueError("wrong delay value")
        try:
            return Decimal(arr[0]), Decimal(arr[1])
        except InvalidOperation:
            raise ValueError("wrong delay value") from None
    raise ValueError("wrong delay value")


def is_valid_calc_var_wei_value(value: str | None, base_name: str = "var", decimals: int | None = None) -> bool:
    if value is None:
        return True  # check for None on BaseModel.field type level
    try:
        calcs.calc_var_wei_value(value, var_value=123, var_name=base_name, decimals=decimals)
        return True  # noqa: TRY300
    except ValueError:
        return False


def is_valid_calc_decimal_value(value: str | None) -> bool:
    if value is None:
        return True  # check for None on BaseModel.field type level
    try:
        calcs.calc_decimal_value(value)
        return True  # noqa: TRY300
    except ValueError:
        return False


def is_valid_calc_function_args(value: str | None) -> bool:
    if value is None:
        return True
    try:
        calcs.calc_function_args(value)
        return True  # noqa: TRY300
    except ValueError:
        return False
