import asyncio
import importlib.metadata
from typing import Annotated

import typer
from mm_std import PrintFormat, print_plain

from mm_eth.account import DEFAULT_DERIVATION_PATH
from mm_eth.cli.cmd.wallet import mnemonic_cmd, private_key_cmd
from mm_eth.cli.cmd import node_cmd

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


def version_callback(value: bool) -> None:
    if value:
        print_plain(f"mm-eth: {importlib.metadata.version('mm-eth')}")
        raise typer.Exit


@app.callback()
def main(_version: bool = typer.Option(None, "--version", callback=version_callback, is_eager=True)) -> None:
    pass


if __name__ == "__main_":
    app()
