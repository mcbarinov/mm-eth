from enum import Enum
from typing import Annotated

import typer
from mm_std import PrintFormat, print_plain

from . import cli_utils
from .cmd import (
    balance_cmd,
    balances_cmd,
    call_contract_cmd,
    config_example_cmd,
    deploy_cmd,
    encode_input_data_cmd,
    mnemonic_cmd,
    node_cmd,
    private_key_cmd,
    rpc_cmd,
    send_contract_cmd,
    solc_cmd,
    token_cmd,
    transfer_erc20_cmd,
    transfer_eth_cmd,
    vault_cmd,
)

app = typer.Typer(no_args_is_help=True, pretty_exceptions_enable=False, add_completion=False)

wallet_app = typer.Typer(no_args_is_help=True, help="Wallet commands: generate mnemonic, private to address")
app.add_typer(wallet_app, name="wallet")
app.add_typer(wallet_app, name="w", hidden=True)


class ConfigExample(str, Enum):
    TRANSFER_ETH = "transfer-eth"
    TRANSFER_ERC20 = "transfer-erc20"
    BALANCES = "balances"
    CALL_CONTRACT = "call-contract"


@app.command(name="balance", help="Gen account balance")
def balance_command(
    wallet_address: Annotated[str, typer.Argument()],
    token_address: Annotated[str | None, typer.Option("--token", "-t")] = None,
    rpc_url: Annotated[str, typer.Option("--url", "-u", envvar="ETH_RPC_URL")] = "",  # nosec
    wei: bool = typer.Option(False, "--wei", "-w", help="Print balances in wei units"),
    print_format: Annotated[PrintFormat, typer.Option("--format", "-f", help="Print format")] = PrintFormat.PLAIN,
) -> None:
    balance_cmd.run(rpc_url, wallet_address, token_address, wei, print_format)


@app.command(name="token", help="Get token info")
def token_command(
    token_address: Annotated[str, typer.Argument()],
    rpc_url: Annotated[str, typer.Option("--url", "-u", envvar="ETH_RPC_URL")] = "",
) -> None:
    token_cmd.run(rpc_url, token_address)


@app.command(name="node", help="Check RPC url")
def node_command(
    urls: Annotated[list[str], typer.Argument()],
    print_format: Annotated[PrintFormat, typer.Option("--format", "-f", help="Print format")] = PrintFormat.TABLE,
    proxy: Annotated[str | None, typer.Option("--proxy", "-p", help="Proxy")] = None,
) -> None:
    node_cmd.run(urls, print_format, proxy)


@wallet_app.command(name="mnemonic", help="Generate eth accounts based on a mnemonic")
def mnemonic_command(  # nosec
    mnemonic: Annotated[str, typer.Option("--mnemonic", "-m")] = "",
    passphrase: Annotated[str, typer.Option("--passphrase", "-pass")] = "",
    print_path: bool = typer.Option(False, "--print_path"),
    path_prefix: Annotated[str, typer.Option("--path")] = "m/44'/60'/0'/0",
    limit: int = typer.Option(10, "--limit", "-l"),
    save_file: str = typer.Option("", "--save", "-s", help="Save private keys to a file"),
) -> None:
    mnemonic_cmd.run(
        mnemonic,
        passphrase=passphrase,
        print_path=print_path,
        limit=limit,
        path_prefix=path_prefix,
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
    keys_file: Annotated[str, typer.Option(..., "--file", "-f", help="Path to a file with private keys")],
) -> None:
    vault_cmd.run(keys_url, vault_token, keys_file)


@app.command(name="rpc", help="Call a JSON-RPC method")
def rpc_command(
    method: Annotated[str, typer.Argument()] = "",
    params: Annotated[str, typer.Argument()] = "[]",
    rpc_url: Annotated[str, typer.Option("--url", "-u", envvar="ETH_RPC_URL", help="RPC node url")] = "",
    hex2dec: Annotated[bool, typer.Option("--hex2dec", "-d", help="Print result in decimal value")] = False,
) -> None:
    rpc_cmd.run(rpc_url, method, params, hex2dec)


@app.command(name="transfer-eth", help="Transfer eth / base token from one or many accounts")
def transfer_eth_command(
    config_path: str,
    print_balances: bool = typer.Option(False, "--balances", "-b", help="Print balances and exit"),
    print_config: bool = typer.Option(False, "--config", "-c", help="Print config and exit"),
    emulate: bool = typer.Option(False, "--emulate", "-e", help="Emulate transaction posting"),
    no_receipt: bool = typer.Option(False, "--no-receipt", "-nr", help="Don't wait for a tx receipt"),
    debug: bool = typer.Option(False, "--debug", "-d", help="Print debug info"),
) -> None:
    transfer_eth_cmd.run(
        config_path,
        print_balances=print_balances,
        print_config=print_config,
        debug=debug,
        no_receipt=no_receipt,
        emulate=emulate,
    )


@app.command(name="transfer-erc20", help="Transfer ERC20 token from one or many accounts")
def transfer_erc20_command(
    config_path: str,
    print_balances: bool = typer.Option(False, "--balances", "-b", help="Print balances and exit"),
    print_config: bool = typer.Option(False, "--config", "-c", help="Print config and exit"),
    emulate: bool = typer.Option(False, "--emulate", "-e", help="Emulate transaction posting"),
    no_receipt: bool = typer.Option(False, "--no-receipt", "-nr", help="Don't wait for a tx receipt"),
    debug: bool = typer.Option(False, "--debug", "-d", help="Print debug info"),
) -> None:
    transfer_erc20_cmd.run(
        config_path,
        print_balances=print_balances,
        print_config=print_config,
        debug=debug,
        no_receipt=no_receipt,
        emulate=emulate,
    )


@app.command(name="send-contract", help="Send transactions to a contract")
def send_contract_command(
    config_path: str,
    print_balances: bool = typer.Option(False, "--balances", "-b", help="Print balances and exit"),
    print_config: bool = typer.Option(False, "--config", "-c", help="Print config and exit"),
    emulate: bool = typer.Option(False, "--emulate", "-e", help="Emulate transaction posting"),
    no_receipt: bool = typer.Option(False, "--no-receipt", "-nr", help="Don't wait for a tx receipt"),
    debug: bool = typer.Option(False, "--debug", "-d", help="Print debug info"),
) -> None:
    send_contract_cmd.run(
        config_path,
        print_balances=print_balances,
        print_config=print_config,
        debug=debug,
        no_receipt=no_receipt,
        emulate=emulate,
    )


@app.command(name="balances", help="Print base and ERC20 token balances")
def balances_command(
    config_path: str,
    print_config: bool = typer.Option(False, "--config", "-c", help="Print config only and exit"),
    nonce: bool = typer.Option(False, "--nonce", "-n", help="Print nonce also"),
    wei: bool = typer.Option(False, "--wei", "-w", help="Show balances in WEI"),
) -> None:
    balances_cmd.run(config_path, print_config, wei, nonce)


@app.command(name="call-contract", help="Call a method on a contract")
def call_contract_command(
    config_path: str,
    print_config: bool = typer.Option(False, "--config", "-c", help="Print config only and exit"),
) -> None:
    call_contract_cmd.run(config_path, print_config)


@app.command(name="deploy", help="Deploy a smart contract onchain")
def deploy_command(
    config_path: str,
    print_config: bool = typer.Option(False, "--config", "-c", help="Print config only and exit"),
) -> None:
    deploy_cmd.run(config_path, print_config=print_config)


@app.command(name="config-example", help="Print an example of config for a command")
def config_example_command(command: Annotated[ConfigExample, typer.Argument()]) -> None:
    config_example_cmd.run(command)


@app.command(name="encode-input-data", help="Encode input data by a function signature")
def encode_input_data(
    funtion_signature: str = typer.Argument(help="Function signature, for example: transfer(address, uint256)"),
    args_str: str = typer.Argument(
        help="""Function arguments, as an array string. For example: '["0xA659FB44eB5d4bFaC1074Cb426b1b11D58D28308", 123]' """,
    ),
) -> None:
    encode_input_data_cmd.run(funtion_signature, args_str)


def version_callback(value: bool) -> None:
    if value:
        print_plain(f"mm-eth-cli version: {cli_utils.get_version()}")
        raise typer.Exit


@app.callback()
def main(_version: bool = typer.Option(None, "--version", callback=version_callback, is_eager=True)) -> None:
    pass


if __name__ == "__main_":
    app()
