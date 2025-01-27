import importlib.metadata
import sys
from pathlib import Path

from mm_std import BaseConfig, fatal, print_json

from mm_eth import account
from mm_eth.account import is_private_key


def get_version() -> str:
    return importlib.metadata.version("mm-eth")


def public_rpc_url(url: str | None) -> str:
    if not url or url == "1":
        return "https://ethereum.publicnode.com"
    if url.startswith(("http://", "https://", "ws://", "wss://")):
        return url

    match url.lower():
        case "opbnb" | "204":
            return "https://opbnb-mainnet-rpc.bnbchain.org"
        case "base" | "8453":
            return "https://mainnet.base.org"
        case "base-sepolia" | "84532":
            return "https://sepolia.base.org"
        case _:
            return url


def check_private_keys(addresses: list[str], private_keys: dict[str, str]) -> None:
    for address in addresses:
        address = address.lower()  # noqa: PLW2901
        if address not in private_keys:
            fatal(f"no private key for {address}")
        if account.private_to_address(private_keys[address]) != address:
            fatal(f"no private key for {address}")


def load_private_keys_from_file(private_keys_file: str) -> list[str]:
    lines = Path(private_keys_file).expanduser().read_text().split()
    return [line for line in lines if is_private_key(line)]


def print_config_and_exit(exit_: bool, config: BaseConfig, exclude: set[str] | None = None) -> None:
    if exit_:
        print_json(config.model_dump(exclude=exclude))
        sys.exit(0)
