from mm_std import Err, Ok, print_plain

from mm_eth import erc20, rpc
from mm_eth.cli import cli_utils


def run(rpc_url: str, token_address: str) -> None:
    rpc_url = cli_utils.public_rpc_url(rpc_url)
    name = erc20.get_name(rpc_url, token_address).ok_or_err()
    symbol = erc20.get_symbol(rpc_url, token_address).ok_or_err()
    decimals = erc20.get_decimals(rpc_url, token_address).ok_or_err()
    transfer_count = _calc_transfer_events(rpc_url, 100, token_address)

    print_plain(f"name: {name}")
    print_plain(f"symbol: {symbol}")
    print_plain(f"decimals: {decimals}")
    print_plain(f"transfer_count: {transfer_count}")


def _calc_transfer_events(rpc_url: str, last_block_limit: int, token_address: str) -> int | str:
    current_block_res = rpc.eth_block_number(rpc_url)
    if isinstance(current_block_res, Err):
        return current_block_res.err
    current_block = current_block_res.ok

    res = erc20.get_transfer_event_logs(rpc_url, token_address, current_block - last_block_limit, current_block)
    if isinstance(res, Ok):
        return len(res.ok)
    return res.err
