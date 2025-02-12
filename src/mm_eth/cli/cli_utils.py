import importlib.metadata
import time
from pathlib import Path
from typing import Literal

from mm_crypto_utils import Nodes, Proxies
from mm_std import BaseConfig, print_json
from pydantic import BaseModel

from mm_eth import rpc


def get_version() -> str:
    return importlib.metadata.version("mm-eth")


def public_rpc_url(url: str | None) -> str:
    if not url or url == "1":
        return "https://ethereum.publicnode.com"
    if url.startswith(("http://", "https://", "ws://", "wss://")):
        return url

    match url.lower():
        case "mainnet" | "1":
            return "https://ethereum.publicnode.com"
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


def print_config(config: BaseConfig, exclude: set[str] | None = None, count: set[str] | None = None) -> None:
    data = config.model_dump(exclude=exclude)
    if count:
        for k in count:
            data[k] = len(data[k])
    print_json(data)


def wait_tx_status(nodes: Nodes, proxies: Proxies, tx_hash: str, timeout: int) -> Literal["OK", "FAIL", "TIMEOUT"]:
    started_at = time.perf_counter()
    count = 0
    while True:
        res = rpc.get_tx_status(nodes, tx_hash, proxies=proxies, attempts=5)
        if res.is_ok():
            return "OK" if res.ok == 1 else "FAIL"

        time.sleep(1)
        count += 1
        if time.perf_counter() - started_at > timeout:
            return "TIMEOUT"
