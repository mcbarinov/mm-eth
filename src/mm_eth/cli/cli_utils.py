import importlib.metadata
import sys
from pathlib import Path

import eth_utils
from loguru import logger
from mm_std import BaseConfig, fatal, print_json, str_to_list

from mm_eth import account
from mm_eth.account import is_private_key


def get_version() -> str:
    return importlib.metadata.version("mm-eth-cli")


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


def check_private_keys(addresses: list[str], private_keys: dict[str, str]) -> None:
    for address in addresses:
        address = address.lower()  # noqa: PLW2901
        if address not in private_keys:
            fatal(f"no private key for {address}")
        if account.private_to_address(private_keys[address]) != address:
            fatal(f"no private key for {address}")


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
    lines = Path(private_keys_file).expanduser().read_text().split()
    return [line for line in lines if is_private_key(line)]


def print_config_and_exit(exit_: bool, config: BaseConfig, exclude: set[str] | None = None) -> None:
    if exit_:
        print_json(config.model_dump(exclude=exclude))
        sys.exit(0)
