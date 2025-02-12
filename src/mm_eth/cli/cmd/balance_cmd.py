from mm_std import PrintFormat, print_json, print_plain

from mm_eth import erc20, rpc
from mm_eth.cli.cli_utils import public_rpc_url
from mm_eth.utils import from_wei_str


def run(rpc_url: str, wallet_address: str, token_address: str | None, wei: bool, print_format: PrintFormat) -> None:
    result: dict[str, object] = {}
    rpc_url = public_rpc_url(rpc_url)

    # nonce
    result["nonce"] = rpc.eth_get_transaction_count(rpc_url, wallet_address).ok_or_err()
    if print_format == PrintFormat.PLAIN:
        print_plain(f"nonce: {result['nonce']}")

    # eth balance
    result["eth_balance"] = (
        rpc.eth_get_balance(rpc_url, wallet_address).map(lambda x: str(x) if wei else from_wei_str(x, "eth")).ok_or_err()
    )
    if print_format == PrintFormat.PLAIN:
        print_plain(f"eth_balance: {result['eth_balance']}")

    if token_address:
        # token decimal
        result["token_decimal"] = erc20.get_decimals(rpc_url, token_address).ok_or_err()
        if print_format == PrintFormat.PLAIN:
            print_plain(f"token_decimal: {result['token_decimal']}")

        # token symbol
        result["token_symbol"] = erc20.get_symbol(rpc_url, token_address).ok_or_err()
        if print_format == PrintFormat.PLAIN:
            print_plain(f"token_symbol: {result['token_symbol']}")

        # token balance
        result["token_balance"] = (
            erc20.get_balance(rpc_url, token_address, wallet_address)
            .map(
                lambda x: str(x) if wei or not result["token_decimal"] else from_wei_str(x, "t", decimals=result["token_decimal"])  # type: ignore[arg-type]
            )
            .ok_or_err()
        )
        if print_format == PrintFormat.PLAIN:
            print_plain(f"token_balance: {result['token_balance']}")

    if print_format == PrintFormat.JSON:
        print_json(data=result)
