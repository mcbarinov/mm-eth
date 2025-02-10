from collections.abc import Callable

from mm_crypto_utils import AddressToPrivate, ConfigValidators, Transfer

from mm_eth.account import address_from_private, is_address
from mm_eth.constants import SUFFIX_DECIMALS

from . import calcs


class Validators(ConfigValidators):
    @staticmethod
    def valid_eth_expression(var_name: str | None = None) -> Callable[[str], str]:
        return ConfigValidators.valid_calc_int_expression(var_name, SUFFIX_DECIMALS)

    @staticmethod
    def valid_token_expression(var_name: str | None = None) -> Callable[[str], str]:
        return ConfigValidators.valid_calc_int_expression(var_name, {"t": 6})

    @staticmethod
    def valid_eth_or_token_expression(var_name: str | None = None) -> Callable[[str], str]:
        return ConfigValidators.valid_calc_int_expression(var_name, SUFFIX_DECIMALS | {"t": 6})

    @staticmethod
    def eth_transfers() -> Callable[[str], list[Transfer]]:
        return ConfigValidators.transfers(is_address, to_lower=True)

    @staticmethod
    def eth_private_keys() -> Callable[[str], AddressToPrivate]:
        return ConfigValidators.private_keys(address_from_private)

    @staticmethod
    def eth_address() -> Callable[[str], str]:
        return ConfigValidators.address(is_address, to_lower=True)

    @staticmethod
    def eth_addresses(unique: bool) -> Callable[[str], list[str]]:
        return ConfigValidators.addresses(unique, to_lower=True, is_address=is_address)


def is_valid_calc_function_args(value: str | None) -> bool:
    if value is None:
        return True
    try:
        calcs.calc_function_args(value)
        return True  # noqa: TRY300
    except ValueError:
        return False
