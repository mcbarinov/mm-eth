from mm_std import Err, Ok, PrintFormat, fatal, print_json, print_plain

from mm_eth import erc20, rpc
from mm_eth.cli.cli_utils import public_rpc_url
from mm_eth.utils import from_wei_str


def run(rpc_url: str, wallet_address: str, token_address: str | None, wei: bool, print_format: PrintFormat) -> None:
    rpc_url = public_rpc_url(rpc_url)
    json_result: dict[str, object] = {}

    # nonce
    nonce = rpc.eth_get_transaction_count(rpc_url, wallet_address).ok_or_err()
    print_plain(f"nonce: {nonce}", print_format)
    json_result["nonce"] = nonce

    # balance
    balance_res = rpc.eth_get_balance(rpc_url, wallet_address)
    if isinstance(balance_res, Ok):
        balance = str(balance_res.ok) if wei else from_wei_str(balance_res.ok, "eth")
    else:
        balance = balance_res.err
    print_plain(f"eth_balance: {balance}", print_format)
    json_result["eth_balance"] = balance

    if token_address is not None:
        # token decimal
        decimals_res = erc20.get_decimals(rpc_url, token_address)
        if isinstance(decimals_res, Err):
            fatal(f"error: can't get token decimals: {decimals_res.err}")
        decimals = decimals_res.ok
        print_plain(f"token_decimal: {decimals}", print_format)
        json_result["token_decimal"] = decimals

        # token symbol
        symbol_res = erc20.get_symbol(rpc_url, token_address)
        if isinstance(symbol_res, Err):
            fatal(f"error: can't get token symbol: {symbol_res.err}")
        symbol = symbol_res.ok
        print_plain(f"token_symbol: {symbol}", print_format)
        json_result["token_symbol"] = symbol

        # token balance
        balance_res = erc20.get_balance(rpc_url, token_address, wallet_address)
        if isinstance(balance_res, Err):
            fatal(f"error: can't get token balance: {balance_res.err}")
        balance = str(balance_res.ok) if wei else from_wei_str(balance_res.ok, "t", decimals=decimals)
        print_plain(f"token_balance: {balance}", print_format)
        json_result["token_balance"] = balance

    print_json(json_result, print_format)
