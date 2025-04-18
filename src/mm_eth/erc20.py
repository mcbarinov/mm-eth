import eth_abi
import eth_utils
from eth_typing import HexStr

from mm_eth import tx
from mm_eth.tx import SignedTx

TRANSFER_METHOD = "0xa9059cbb"
TRANSFER_TOPIC = HexStr("0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef")


def encode_transfer_input_data(recipient: str, value: int) -> str:
    recipient = eth_utils.to_checksum_address(recipient)
    input_data = eth_utils.to_bytes(hexstr=HexStr(TRANSFER_METHOD)) + eth_abi.encode(["address", "uint256"], [recipient, value])
    return eth_utils.to_hex(input_data)


def sign_transfer_tx(
    *,
    token_address: str,
    recipient_address: str,
    value: int,
    nonce: int,
    max_fee_per_gas: int,
    max_priority_fee_per_gas: int,
    gas_limit: int,
    private_key: str,
    chain_id: int,
) -> SignedTx:
    input_data = encode_transfer_input_data(recipient_address, value)
    return tx.sign_tx(
        nonce=nonce,
        max_fee_per_gas=max_fee_per_gas,
        max_priority_fee_per_gas=max_priority_fee_per_gas,
        gas=gas_limit,
        private_key=private_key,
        chain_id=chain_id,
        data=input_data,
        to=token_address,
    )
