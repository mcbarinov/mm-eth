"""Smart contract deployment helpers."""

import eth_utils
import rlp
from eth_utils import keccak

from mm_eth import abi


def get_deploy_contract_data(contract_bin: str, constructor_types: list[str], constructor_values: list[object]) -> str:
    """Build deployment bytecode by appending ABI-encoded constructor arguments to contract binary."""
    constructor_data = ""
    if constructor_types and constructor_values:
        constructor_data = abi.encode_data(constructor_types, constructor_values)[2:]
    return contract_bin + constructor_data


def get_contract_address(sender_address: str, nonce: int) -> str:
    """Compute the contract address that would be created by a given sender and nonce."""
    sender_bytes = eth_utils.to_bytes(hexstr=sender_address)
    raw = rlp.encode([sender_bytes, nonce])
    h = keccak(raw)
    address_bytes = h[12:]
    return eth_utils.to_checksum_address(address_bytes).lower()
