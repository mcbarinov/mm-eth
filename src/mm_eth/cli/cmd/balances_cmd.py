from dataclasses import dataclass
from typing import Annotated

import mm_print
from mm_web3 import Web3CliConfig
from pydantic import BeforeValidator
from rich.live import Live
from rich.table import Table

from mm_eth import converters, retry
from mm_eth.cli.cli_utils import BaseConfigParams
from mm_eth.cli.validators import Validators


class Config(Web3CliConfig):
    addresses: Annotated[list[str], BeforeValidator(Validators.eth_addresses(unique=True))]
    tokens: Annotated[list[str], BeforeValidator(Validators.eth_addresses(unique=True))]
    nodes: Annotated[list[str], BeforeValidator(Validators.nodes())]
    round_ndigits: int = 5


@dataclass
class Token:
    address: str
    decimals: int
    symbol: str


class BalancesCmdParams(BaseConfigParams):
    wei: bool
    show_nonce: bool


async def run(params: BalancesCmdParams) -> None:
    config = Config.read_toml_config_or_exit(params.config_path)
    if params.print_config:
        config.print_and_exit()

    tokens = await _get_tokens_info(config)

    table = Table(title="balances")
    table.add_column("address")
    if params.show_nonce:
        table.add_column("nonce")
    table.add_column("wei" if params.wei else "eth")
    for t in tokens:
        table.add_column(t.symbol)

    base_sum = 0
    token_sum: dict[str, int] = {t.address: 0 for t in tokens}
    with Live(table, refresh_per_second=0.5):
        for address in config.addresses:
            row = [address]
            if params.show_nonce:
                nonce = await retry.eth_get_transaction_count(5, config.nodes, None, address=address)
                row.append(str(nonce.value_or_error()))

            base_balance_res = await retry.eth_get_balance(5, config.nodes, None, address=address)
            if base_balance_res.is_ok():
                balance = base_balance_res.unwrap()
                base_sum += balance
                if params.wei:
                    row.append(str(balance))
                else:
                    row.append(str(converters.from_wei(balance, "eth", round_ndigits=config.round_ndigits)))
            else:
                row.append(base_balance_res.unwrap_err())

            for t in tokens:
                token_balance_res = await retry.erc20_balance(5, config.nodes, None, token=t.address, wallet=address)
                if token_balance_res.is_ok():
                    token_balance = token_balance_res.unwrap()
                    token_sum[t.address] += token_balance
                    if params.wei:
                        row.append(str(token_balance))
                    else:
                        row.append(
                            str(converters.from_wei(token_balance, "t", round_ndigits=config.round_ndigits, decimals=t.decimals))
                        )
                else:
                    row.append(token_balance_res.unwrap_err())

            table.add_row(*row)

        sum_row = ["sum"]
        if params.show_nonce:
            sum_row.append("")
        if params.wei:
            sum_row.append(str(base_sum))
            sum_row.extend([str(token_sum[t.address]) for t in tokens])
        else:
            sum_row.append(str(converters.from_wei(base_sum, "eth", round_ndigits=config.round_ndigits)))
            sum_row.extend(
                [
                    str(converters.from_wei(token_sum[t.address], "t", round_ndigits=config.round_ndigits, decimals=t.decimals))
                    for t in tokens
                ]
            )

        table.add_row(*sum_row)


async def _get_tokens_info(config: Config) -> list[Token]:
    result: list[Token] = []
    for address in config.tokens:
        decimals_res = await retry.erc20_decimals(5, config.nodes, None, token=address)
        if decimals_res.is_err():
            mm_print.fatal(f"can't get token {address} decimals: {decimals_res.unwrap_err()}")
        decimal = decimals_res.unwrap()

        symbols_res = await retry.erc20_symbol(5, config.nodes, None, token=address)
        if symbols_res.is_err():
            mm_print.fatal(f"can't get token {address} symbol: {symbols_res.unwrap_err()}")
        symbol = symbols_res.unwrap()

        result.append(Token(address=address, decimals=decimal, symbol=symbol))

    return result
