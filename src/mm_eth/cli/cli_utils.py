import importlib.metadata
from enum import Enum, unique
from pathlib import Path

import mm_print
from pydantic import BaseModel
from rich.table import Table

from mm_eth import rpc


@unique
class PrintFormat(str, Enum):
    PLAIN = "plain"
    TABLE = "table"
    JSON = "json"


def public_rpc_url(url: str | None) -> str:
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
    config_path: Path
    print_config: bool


async def check_nodes_for_chain_id(nodes: list[str], chain_id: int) -> None:
    for node in nodes:
        res = (await rpc.eth_chain_id(node)).unwrap("can't get chain_id")
        if res != chain_id:
            mm_print.fatal(f"node {node} has a wrong chain_id: {res}")


def add_table_raw(table: Table, *row: object) -> None:
    table.add_row(*[str(cell) for cell in row])


def get_version() -> str:
    return importlib.metadata.version("mm-eth")
