from enum import Enum
from pathlib import Path
from typing import Annotated

import typer
from mm_std import PrintFormat, print_plain

from mm_eth.account import DEFAULT_DERIVATION_PATH

from . import cli_utils
from .cmd import (
    balance_cmd,
    balances_cmd,
    call_contract_cmd,
    deploy_cmd,
    encode_input_data_cmd,
    example_cmd,
    node_cmd,
    rpc_cmd,
    solc_cmd,
    token_cmd,
    transfer_cmd,
    tx_cmd,
    vault_cmd,
)
from .cmd.balances_cmd import BalancesCmdParams
from .cmd.call_contract_cmd import CallContractCmdParams
from .cmd.deploy_cmd import DeployCmdParams
from .cmd.transfer_cmd import TransferCmdParams
from .cmd.wallet import mnemonic_cmd, private_key_cmd

app = typer.Typer(no_args_is_help=True, pretty_exceptions_enable=False, add_completion=False)

wallet_app = typer.Typer(no_args_is_help=True, help="Wallet commands: generate mnemonic, private to address")
app.add_typer(wallet_app, name="wallet")
app.add_typer(wallet_app, name="w", hidden=True)


class ConfigExample(str, Enum):
    TRANSFER = "transfer"
    BALANCES = "balances"
    CALL_CONTRACT = "call-contract"


@app.command(name="balance", help="Gen account balance")
def balance_command(
    wallet_address: Annotated[str, typer.Argument()],
    token_address: Annotated[str | None, typer.Option("--token", "-t")] = None,
    rpc_url: Annotated[str, typer.Option("--url", "-u", envvar="MM_ETH_RPC_URL")] = "",  # nosec
    wei: bool = typer.Option(False, "--wei", "-w", help="Print balances in wei units"),
    print_format: Annotated[PrintFormat, typer.Option("--format", "-f", help="Print format")] = PrintFormat.PLAIN,
) -> None:
    balance_cmd.run(rpc_url, wallet_address, token_address, wei, print_format)


@app.command(name="balances", help="Print base and ERC20 token balances")
def balances_command(
    config_path: Path,
    print_config: bool = typer.Option(False, "--config", "-c", help="Print config and exit"),
    nonce: bool = typer.Option(False, "--nonce", "-n", help="Print nonce also"),
    wei: bool = typer.Option(False, "--wei", "-w", help="Show balances in WEI"),
) -> None:
    balances_cmd.run(BalancesCmdParams(config_path=config_path, print_config=print_config, wei=wei, show_nonce=nonce))


@app.command(name="token", help="Get token info")
def token_command(
    token_address: Annotated[str, typer.Argument()],
    rpc_url: Annotated[str, typer.Option("--url", "-u", envvar="MM_ETH_RPC_URL")] = "",
) -> None:
    token_cmd.run(rpc_url, token_address)


@app.command(name="node", help="Check RPC url")
def node_command(
    urls: Annotated[list[str], typer.Argument()],
    proxy: Annotated[str | None, typer.Option("--proxy", "-p", help="Proxy")] = None,
    print_format: Annotated[PrintFormat, typer.Option("--format", "-f", help="Print format")] = PrintFormat.TABLE,
) -> None:
    node_cmd.run(urls, proxy, print_format)


@wallet_app.command(name="mnemonic", help="Generate eth accounts based on a mnemonic")
def mnemonic_command(  # nosec
    mnemonic: Annotated[str, typer.Option("--mnemonic", "-m")] = "",
    passphrase: Annotated[str, typer.Option("--passphrase", "-p")] = "",
    print_path: bool = typer.Option(False, "--print_path"),
    derivation_path: Annotated[str, typer.Option("--path")] = DEFAULT_DERIVATION_PATH,
    words: int = typer.Option(12, "--words", "-w", help="Number of mnemonic words"),
    limit: int = typer.Option(10, "--limit", "-l"),
    save_file: str = typer.Option("", "--save", "-s", help="Save private keys to a file"),
) -> None:
    mnemonic_cmd.run(
        mnemonic,
        passphrase=passphrase,
        print_path=print_path,
        limit=limit,
        words=words,
        derivation_path=derivation_path,
        save_file=save_file,
    )


@wallet_app.command(name="private-key", help="Print an address for a private key")
def private_key_command(private_key: str) -> None:
    private_key_cmd.run(private_key)


@app.command(name="solc", help="Compile a solidity file")
def solc_command(
    contract_path: str,
    tmp_dir: str = "/tmp",  # noqa: S108 # nosec
    print_format: Annotated[PrintFormat, typer.Option("--format", "-f", help="Print format")] = PrintFormat.PLAIN,
) -> None:
    solc_cmd.run(contract_path, tmp_dir, print_format)


@app.command(name="vault", help="Save private keys to vault")
def vault_command(
    keys_url: Annotated[
        str,
        typer.Option(..., "--url", "-u", help="Url to keys, for example https://vault.site.com:8200/v1/kv/keys1"),
    ],
    vault_token: Annotated[
        str,
        typer.Option(..., "--token", "-t", prompt=True, hide_input=True, prompt_required=False, help="A vault token"),
    ],
    keys_file: Annotated[Path, typer.Option(..., "--file", "-f", help="Path to a file with private keys")],
) -> None:
    vault_cmd.run(keys_url, vault_token, keys_file)


@app.command(name="rpc", help="Call a JSON-RPC method")
def rpc_command(
    method: Annotated[str, typer.Argument()] = "",
    params: Annotated[str, typer.Argument()] = "[]",
    rpc_url: Annotated[str, typer.Option("--url", "-u", envvar="MM_ETH_RPC_URL", help="RPC node url")] = "",
    hex2dec: Annotated[bool, typer.Option("--hex2dec", "-d", help="Print result in decimal value")] = False,
) -> None:
    rpc_cmd.run(rpc_url, method, params, hex2dec)


@app.command(name="tx", help="Get transaction info by hash")
def tx_command(
    tx_hash: Annotated[str, typer.Argument()],
    rpc_url: Annotated[str, typer.Option("--url", "-u", envvar="MM_ETH_RPC_URL", help="RPC node url")] = "",
    get_receipt: Annotated[bool, typer.Option("--receipt", "-r", help="Get receipt")] = False,
) -> None:
    tx_cmd.run(rpc_url, tx_hash, get_receipt)


@app.command(
    name="transfer", help="Transfers ETH or ERC20 tokens, supporting multiple routes, delays, and expression-based values"
)
def transfer_command(
    config_path: Path,
    print_balances: bool = typer.Option(False, "--balances", "-b", help="Print balances and exit"),
    print_transfers: bool = typer.Option(False, "--transfers", "-t", help="Print transfers (from, to, value) and exit"),
    print_config: bool = typer.Option(False, "--config", "-c", help="Print config and exit"),
    emulate: bool = typer.Option(False, "--emulate", "-e", help="Emulate transaction posting"),
    skip_receipt: bool = typer.Option(False, "--skip-receipt", help="Don't wait for a tx receipt"),
    debug: bool = typer.Option(False, "--debug", "-d", help="Print debug info"),
) -> None:
    transfer_cmd.run(
        TransferCmdParams(
            config_path=config_path,
            print_balances=print_balances,
            print_transfers=print_transfers,
            print_config=print_config,
            debug=debug,
            skip_receipt=skip_receipt,
            emulate=emulate,
        )
    )


# @app.command(name="send-contract", help="Send transactions to a contract")
# def send_contract_command(
#     config_path: Path,
#     print_balances: bool = typer.Option(False, "--balances", "-b", help="Print balances and exit"),
#     print_config: bool = typer.Option(False, "--config", "-c", help="Print config and exit"),
#     emulate: bool = typer.Option(False, "--emulate", "-e", help="Emulate transaction posting"),
#     no_receipt: bool = typer.Option(False, "--no-receipt", "-nr", help="Don't wait for a tx receipt"),
#     debug: bool = typer.Option(False, "--debug", "-d", help="Print debug info"),
# ) -> None:
#     send_contract_cmd.run(
#         SendContractCmdParams(
#             config_path=config_path,
#             print_balances=print_balances,
#             print_config=print_config,
#             debug=debug,
#             no_receipt=no_receipt,
#             emulate=emulate,
#         )
#     )


@app.command(name="call-contract", help="Call a method on a contract")
def call_contract_command(
    config_path: Path,
    print_config: bool = typer.Option(False, "--config", "-c", help="Print config and exit"),
) -> None:
    call_contract_cmd.run(CallContractCmdParams(config_path=config_path, print_config=print_config))


@app.command(name="deploy", help="Deploy a smart contract onchain")
def deploy_command(
    config_path: Path,
    print_config: bool = typer.Option(False, "--config", "-c", help="Print config and exit"),
) -> None:
    deploy_cmd.run(DeployCmdParams(config_path=config_path, print_config=print_config))


@app.command(name="example", help="Displays an example configuration for a command")
def example_command(command: Annotated[ConfigExample, typer.Argument()]) -> None:
    example_cmd.run(command)


@app.command(name="encode-input-data", help="Encode input data by a function signature")
def encode_input_data(
    function_signature: str = typer.Argument(help="Function signature, for example: transfer(address, uint256)"),
    args_str: str = typer.Argument(
        help="""Function arguments, as an array string. For example: '["0xA659FB44eB5d4bFaC1074Cb426b1b11D58D28308", 123]' """,
    ),
) -> None:
    encode_input_data_cmd.run(function_signature, args_str)


def version_callback(value: bool) -> None:
    if value:
        print_plain(f"mm-eth: {cli_utils.get_version()}")
        raise typer.Exit


@app.callback()
def main(_version: bool = typer.Option(None, "--version", callback=version_callback, is_eager=True)) -> None:
    pass


if __name__ == "__main_":
    app()
