from collections.abc import Callable
from decimal import Decimal

import mm_crypto_utils
from mm_crypto_utils import ConfigValidators

from . import calcs


class Validators(ConfigValidators):
    @staticmethod
    def valid_calc_value(base_name: str = "var", decimals: int | None = None) -> Callable[[str], str]:
        def validator(v: str) -> str:
            calcs.calc_var_value(v, var_value=123, var_name=base_name, decimals=decimals)
            return v

        return validator

    @staticmethod
    def valid_calc_decimal_value() -> Callable[[str], Decimal]:
        def validator(v: str) -> Decimal:
            return mm_crypto_utils.calc_decimal_value(v)

        return validator


def is_valid_calc_var_value(value: str | None, base_name: str = "var", decimals: int | None = None) -> bool:
    if value is None:
        return True  # check for None on BaseModel.field type level
    try:
        calcs.calc_var_value(value, var_value=123, var_name=base_name, decimals=decimals)
        return True  # noqa: TRY300
    except ValueError:
        return False


def is_valid_calc_decimal_value(value: str | None) -> bool:
    if value is None:
        return True  # check for None on BaseModel.field type level
    try:
        mm_crypto_utils.calc_decimal_value(value)
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
