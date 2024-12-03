import sys
import time
from pathlib import Path

import eth_utils
import yaml
from loguru import logger
from mm_std import Err, fatal, str_to_list, utc_now
from pydantic import BaseModel, ConfigDict, ValidationError
from rich.console import Console
from rich.table import Table

from mm_eth import account, rpc
from mm_eth.account import is_private_key
from mm_eth.cli import calcs

# from typing import TypeVar


class BaseConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")


def check_nodes_for_chain_id(nodes: list[str], chain_id: int) -> None:
    for node in nodes:
        res = rpc.eth_chain_id(node, timeout=7)
        if isinstance(res, Err):
            fatal(f"can't get chain_id for {node}, error={res.err}")
        if res.ok != chain_id:
            fatal(f"node {node} has a wrong chain_id: {res.ok}")


def check_private_keys(addresses: list[str], private_keys: dict[str, str]) -> None:
    for address in addresses:
        address = address.lower()
        if address not in private_keys:
            fatal(f"no private key for {address}")
        if account.private_to_address(private_keys[address]) != address:
            fatal(f"no private key for {address}")


def delay(value: str | None) -> None:
    if value is None:
        return
    time.sleep(float(calcs.calc_decimal_value(value)))


def read_config[T](config_cls: type[T], config_path: str) -> T:
    try:
        with open(config_path) as f:
            config = config_cls(**yaml.full_load(f))
            return config
    except ValidationError as err:
        table = Table(title="config validation errors")
        table.add_column("field")
        table.add_column("message")
        for e in err.errors():
            loc = e["loc"]
            field = str(loc[0]) if len(loc) > 0 else ""
            table.add_row(field, e["msg"])
        console = Console()
        console.print(table)
        exit(1)


def log(log_path: str | None, *messages: object) -> None:
    if log_path is None:
        return
    message = ", ".join([str(m) for m in messages])
    message = f"{utc_now()}, {message}\n"
    with open(Path(log_path).expanduser(), "a") as f:
        f.write(message)


def load_tx_addresses_from_str(v: str | None) -> list[tuple[str, str]]:
    result: list[tuple[str, str]] = []
    if v is None:
        return result
    for line in str_to_list(v, remove_comments=True):
        arr = line.split()
        if len(arr) == 2 and eth_utils.is_address(arr[0]) and eth_utils.is_address(arr[1]):
            result.append((arr[0].lower(), arr[1].lower()))
    return result


def load_tx_addresses_from_files(addresses_from_file: str, addresses_to_file: str) -> list[tuple[str, str]]:
    from_file = Path(addresses_from_file).expanduser()
    to_file = Path(addresses_to_file).expanduser()
    if not from_file.is_file():
        raise ValueError(f"can't read addresses from 'addresses_from_file={addresses_from_file}")
    if not to_file.is_file():
        raise ValueError(f"can't read addresses from 'addresses_to_file={addresses_to_file}")

    # get addresses_from
    addresses_from = []
    for line in from_file.read_text().strip().split("\n"):
        if not eth_utils.is_address(line):
            raise ValueError(f"illigal address in addresses_from_file: {line}")
        addresses_from.append(line.lower())

    # get addresses_to
    addresses_to = []
    for line in to_file.read_text().strip().split("\n"):
        if not eth_utils.is_address(line):
            raise ValueError(f"illigal address in addresses_to_file: {line}")
        addresses_to.append(line.lower())

    if len(addresses_from) != len(addresses_to):
        raise ValueError("len(addresses_from) != len(addresses_to)")

    return list(zip(addresses_from, addresses_to, strict=True))


def load_private_keys_from_file(private_keys_file: str) -> list[str]:
    result: list[str] = []
    for item in Path(private_keys_file).expanduser().read_text().split():
        if is_private_key(item):
            result.append(item)
    return result


def init_logger(debug: bool, log_debug_file: str | None, log_info_file: str | None) -> None:
    if debug:
        level = "DEBUG"
        format_ = "<green>{time:YYYY-MM-DD HH:mm:ss}</green> <level>{level}</level> {message}"
    else:
        level = "INFO"
        format_ = "{message}"

    logger.remove()
    logger.add(sys.stderr, format=format_, colorize=True, level=level)
    if log_debug_file:
        logger.add(Path(log_debug_file).expanduser(), format="{time:YYYY-MM-DD HH:mm:ss} {level} {message}")
    if log_info_file:
        logger.add(Path(log_info_file).expanduser(), format="{message}", level="INFO")


def public_rpc_url(url: str | None) -> str:
    if not url or url == "1":
        return "https://ethereum.publicnode.com"
    if url.startswith(("http://", "https://", "ws://", "wss://")):
        return url

    match url.lower():
        case "opbnb" | "204":
            return "https://opbnb-mainnet-rpc.bnbchain.org"
        case _:
            return url
