"""Pydantic validators for Ethereum addresses, keys, and expressions."""

from collections.abc import Callable

import eth_utils
from mm_web3 import ConfigValidators, PrivateKeyMap, Transfer

from mm_eth import account

SUFFIX_DECIMALS = {"eth": 18, "gwei": 9, "ether": 18}


def address_from_private(private_key: str) -> str:
    """Derive a lowercase Ethereum address from a private key."""
    res = account.private_to_address(private_key)
    if res.is_err():
        raise ValueError("invalid private key")
    return res.unwrap().lower()


class Validators(ConfigValidators):
    """Ethereum-specific config validators for addresses, keys, and expressions."""

    @staticmethod
    def valid_eth_expression(var_name: str | None = None) -> Callable[[str], str]:
        """Return a validator for expressions with ETH unit suffixes."""
        return ConfigValidators.expression_with_vars(var_name, SUFFIX_DECIMALS)

    @staticmethod
    def valid_token_expression(var_name: str | None = None) -> Callable[[str], str]:
        """Return a validator for expressions with token unit suffix."""
        return ConfigValidators.expression_with_vars(var_name, {"t": 6})

    @staticmethod
    def valid_eth_or_token_expression(var_name: str | None = None) -> Callable[[str], str]:
        """Return a validator for expressions with ETH or token unit suffixes."""
        return ConfigValidators.expression_with_vars(var_name, SUFFIX_DECIMALS | {"t": 6})

    @staticmethod
    def eth_transfers() -> Callable[[str], list[Transfer]]:
        """Return a validator for Ethereum transfer definitions."""
        return ConfigValidators.transfers(is_address=eth_utils.is_address, lowercase=True)

    @staticmethod
    def eth_private_keys() -> Callable[[str], PrivateKeyMap]:
        """Return a validator for Ethereum private key mappings."""
        return ConfigValidators.private_keys(address_from_private)

    @staticmethod
    def eth_address() -> Callable[[str], str]:
        """Return a validator for a single Ethereum address."""
        return ConfigValidators.address(eth_utils.is_address, lowercase=True)

    @staticmethod
    def eth_addresses(unique: bool) -> Callable[[str], list[str]]:
        """Return a validator for a list of Ethereum addresses."""
        return ConfigValidators.addresses(unique, lowercase=True, is_address=eth_utils.is_address)
