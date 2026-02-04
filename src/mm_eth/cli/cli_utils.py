"""Shared CLI utilities, config base classes, and output helpers."""

import importlib.metadata
from enum import StrEnum, unique
from pathlib import Path
from typing import NoReturn

import typer
from pydantic import BaseModel
from rich.table import Table

from mm_eth import rpc


@unique
class PrintFormat(StrEnum):
    """Output format for CLI commands."""

    PLAIN = "plain"
    TABLE = "table"
    JSON = "json"


def public_rpc_url(url: str | None) -> str:
    """Resolve a network name or alias to a public RPC URL."""
    if not url or url == "1":
        return "https://ethereum-rpc.publicnode.com"
    if url.startswith(("http://", "https://", "ws://", "wss://")):
        return url

    match url.lower():
        case "mainnet" | "1":
            return "https://ethereum-rpc.publicnode.com"
        case "sepolia" | "11155111":
            return "https://ethereum-sepolia-rpc.publicnode.com"
        case "opbnb" | "204":
            return "https://opbnb-mainnet-rpc.bnbchain.org"
        case "base" | "8453":
            return "https://mainnet.base.org"
        case "base-sepolia" | "84532":
            return "https://sepolia.base.org"
        case _:
            return url


class BaseConfigParams(BaseModel):
    """Base parameters shared by CLI commands that read a config file."""

    config_path: Path
    print_config: bool


async def check_nodes_for_chain_id(nodes: list[str], chain_id: int) -> None:
    """Validate that all nodes return the expected chain ID, exiting on mismatch."""
    for node in nodes:
        res = (await rpc.eth_chain_id(node)).unwrap("can't get chain_id")
        if res != chain_id:
            fatal(f"node {node} has a wrong chain_id: {res}")


def add_table_raw(table: Table, *row: object) -> None:
    """Add a row to a Rich table, converting all values to strings."""
    table.add_row(*[str(cell) for cell in row])


def get_version() -> str:
    """Return the installed mm-eth package version."""
    return importlib.metadata.version("mm-eth")


def fatal(message: str) -> NoReturn:
    """Print an error message and exit with code 1."""
    typer.echo(message)
    raise typer.Exit(1)
