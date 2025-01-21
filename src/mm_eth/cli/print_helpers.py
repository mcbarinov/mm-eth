from rich.live import Live
from rich.table import Table

from mm_eth import erc20, rpc
from mm_eth.utils import from_wei_str


def print_balances(
    rpc_nodes: list[str],
    addresses: list[str],
    *,
    token_address: str | None = None,
    token_decimals: int | None = None,
    round_ndigits: int = 5,
) -> None:
    table = Table(title="balances")
    table.add_column("n")
    table.add_column("address")
    table.add_column("nonce")
    table.add_column("balance, eth")
    if token_address is not None and token_decimals is not None:
        table.add_column("token, t")
    with Live(table, refresh_per_second=0.5):
        for count, address in enumerate(addresses):
            nonce = str(rpc.eth_get_transaction_count(rpc_nodes, address, attempts=5).ok_or_err())
            balance = rpc.eth_get_balance(rpc_nodes, address, attempts=5).map_or_else(
                lambda err: err,
                lambda ok: from_wei_str(ok, "eth", round_ndigits),
            )
            row: list[str] = [str(count), address, nonce, balance]
            if token_address is not None and token_decimals is not None:
                erc20_balance = erc20.get_balance(rpc_nodes, token_address, address, attempts=5).map_or_else(
                    lambda err: err,
                    lambda ok: from_wei_str(ok, "t", decimals=token_decimals, round_ndigits=round_ndigits),
                )
                row.append(erc20_balance)
            table.add_row(*row)
