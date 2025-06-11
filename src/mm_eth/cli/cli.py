import asyncio
import importlib.metadata
from pathlib import Path
from typing import Annotated

import mm_print
import typer

from mm_eth.account import DEFAULT_DERIVATION_PATH
from mm_eth.cli.cli_utils import PrintFormat
from mm_eth.cli.cmd import balance_cmd, balances_cmd, deploy_cmd, node_cmd, solc_cmd, transfer_cmd
from mm_eth.cli.cmd.balances_cmd import BalancesCmdParams
from mm_eth.cli.cmd.deploy_cmd import DeployCmdParams
from mm_eth.cli.cmd.transfer_cmd import TransferCmdParams
from mm_eth.cli.cmd.wallet import mnemonic_cmd, private_key_cmd

app = typer.Typer(no_args_is_help=True, pretty_exceptions_enable=False, add_completion=False)

wallet_app = typer.Typer(no_args_is_help=True, help="Wallet commands: generate mnemonic, private to address")
app.add_typer(wallet_app, name="wallet")
app.add_typer(wallet_app, name="w", hidden=True)


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


@app.command(name="node", help="Check RPC url")
def node_command(
    urls: Annotated[list[str], typer.Argument()],
    proxy: Annotated[str | None, typer.Option("--proxy", "-p", help="Proxy")] = None,
    print_format: Annotated[PrintFormat, typer.Option("--format", "-f", help="Print format")] = PrintFormat.TABLE,
) -> None:
    asyncio.run(node_cmd.run(urls, proxy, print_format))


@app.command(name="balance", help="Gen account balance")
def balance_command(
    wallet_address: Annotated[str, typer.Argument()],
    token_address: Annotated[str | None, typer.Option("--token", "-t")] = None,
    rpc_url: Annotated[str, typer.Option("--url", "-u", envvar="MM_ETH_RPC_URL")] = "",  # nosec
    wei: bool = typer.Option(False, "--wei", "-w", help="Print balances in wei units"),
    print_format: Annotated[PrintFormat, typer.Option("--format", "-f", help="Print format")] = PrintFormat.PLAIN,
) -> None:
    asyncio.run(balance_cmd.run(rpc_url, wallet_address, token_address, wei, print_format))


@app.command(name="balances", help="Print base and ERC20 token balances")
def balances_command(
    config_path: Path,
    print_config: bool = typer.Option(False, "--config", "-c", help="Print config and exit"),
    nonce: bool = typer.Option(False, "--nonce", "-n", help="Print nonce also"),
    wei: bool = typer.Option(False, "--wei", "-w", help="Show balances in WEI"),
) -> None:
    asyncio.run(
        balances_cmd.run(BalancesCmdParams(config_path=config_path, print_config=print_config, wei=wei, show_nonce=nonce))
    )


@app.command(name="solc", help="Compile a solidity file")
def solc_command(
    contract_path: Path,
    tmp_dir: Path = Path("/tmp"),  # noqa: S108 # nosec
    print_format: Annotated[PrintFormat, typer.Option("--format", "-f", help="Print format")] = PrintFormat.PLAIN,
) -> None:
    solc_cmd.run(contract_path, tmp_dir, print_format)


@app.command(name="deploy", help="Deploy a smart contract onchain")
def deploy_command(
    config_path: Path,
    print_config: bool = typer.Option(False, "--config", "-c", help="Print config and exit"),
) -> None:
    asyncio.run(deploy_cmd.run(DeployCmdParams(config_path=config_path, print_config=print_config)))


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
    asyncio.run(
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
    )


def version_callback(value: bool) -> None:
    if value:
        mm_print.plain(f"mm-eth: {importlib.metadata.version('mm-eth')}")
        raise typer.Exit


@app.callback()
def main(_version: bool = typer.Option(None, "--version", callback=version_callback, is_eager=True)) -> None:
    pass


if __name__ == "__main_":
    app()
