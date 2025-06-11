import eth_utils
import mm_print

from mm_eth import converters, rpc
from mm_eth.cli import cli_utils
from mm_eth.cli.cli import PrintFormat


async def run(rpc_url: str, wallet_address: str, token_address: str | None, wei: bool, print_format: PrintFormat) -> None:
    result: dict[str, object] = {}
    rpc_url = cli_utils.public_rpc_url(rpc_url)

    # nonce
    result["nonce"] = (await rpc.eth_get_transaction_count(rpc_url, wallet_address)).value_or_error()
    if print_format == PrintFormat.PLAIN:
        mm_print.plain(f"nonce: {result['nonce']}")

    # eth balance
    result["eth_balance"] = (
        (await rpc.eth_get_balance(rpc_url, wallet_address))
        .map(lambda value: value if wei else eth_utils.from_wei(value, "ether"))
        .value_or_error()
    )
    if print_format == PrintFormat.PLAIN:
        mm_print.plain(f"eth_balance: {result['eth_balance']}")

    if token_address:
        # token decimal
        result["token_decimal"] = (await rpc.erc20_decimals(rpc_url, token_address)).value_or_error()
        if print_format == PrintFormat.PLAIN:
            mm_print.plain(f"token_decimal: {result['token_decimal']}")

        # token symbol
        result["token_symbol"] = (await rpc.erc20_symbol(rpc_url, token_address)).value_or_error()
        if print_format == PrintFormat.PLAIN:
            mm_print.plain(f"token_symbol: {result['token_symbol']}")

        # token balance
        result["token_balance"] = (await rpc.erc20_balance(rpc_url, token_address, wallet_address)).value_or_error()
        if isinstance(result["token_balance"], int) and not wei and isinstance(result["token_decimal"], int):
            result["token_balance"] = converters.from_wei(result["token_balance"], "t", decimals=result["token_decimal"])

        if print_format == PrintFormat.PLAIN:
            mm_print.plain(f"token_balance: {result['token_balance']}")

    if print_format == PrintFormat.JSON:
        mm_print.json(data=result)
