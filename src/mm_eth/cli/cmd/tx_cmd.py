from eth_typing import HexStr
from rich.pretty import pprint
from web3 import Web3

from mm_eth.cli.cli_utils import public_rpc_url


def run(rpc_url: str, tx_hash: str, get_receipt: bool) -> None:
    rpc_url = public_rpc_url(rpc_url)
    w3 = Web3(Web3.HTTPProvider(rpc_url))
    transaction = w3.eth.get_transaction(HexStr(tx_hash))
    pprint(dict(transaction), expand_all=True)

    if get_receipt:
        receipt = w3.eth.get_transaction_receipt(HexStr(tx_hash))
        pprint(dict(receipt), expand_all=True)
