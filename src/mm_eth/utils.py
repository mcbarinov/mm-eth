import re
from decimal import Decimal, localcontext
from typing import Any, cast

import eth_utils
import pydash
from eth_typing import HexStr
from hexbytes import HexBytes
from mm_std import Err, Ok, Result, number_with_separator, random_choice
from mm_std.random_ import random_str_choice
from pydantic import BaseModel
from web3 import Web3
from web3.types import Wei

from mm_eth.types import Nodes, Proxies


def parse_addresses(data: str) -> list[str]:
    result = []
    for word in data.lower().split():
        if len(word) == 42 and re.match("0x[a-f0-9]{40}", word):
            result.append(word)  # noqa: PERF401
    return pydash.uniq(result)


def to_token_wei(value: str | int, decimals: int) -> int:
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        value = value.lower().replace(" ", "").strip()
        if value.endswith("t"):
            value = value.replace("t", "")
            return int(Decimal(value) * 10**decimals)
        if value.isdigit():
            return int(value)

    raise ValueError("wrong value" + value)


def to_wei(value: str | int | Decimal, decimals: int | None = None) -> Wei:
    if isinstance(value, int):
        return Wei(value)
    if isinstance(value, Decimal):
        if value != value.to_integral_value():
            raise ValueError(f"value must be integral number: {value}")
        return Wei(int(value))
    if isinstance(value, str):
        value = value.lower().replace(" ", "").strip()
        if value.endswith("navax"):  # https://snowtrace.io/unitconverter
            value = value.replace("navax", "")
            return Wei(int(Decimal(value) * 10**9))
        if value.endswith("gwei"):
            value = value.replace("gwei", "")
            return Wei(int(Decimal(value) * 1000000000))
        if value.endswith("ether"):
            value = value.replace("ether", "")
            return Wei(int(Decimal(value) * 1000000000000000000))
        if value.endswith("eth"):
            value = value.replace("eth", "")
            return Wei(int(Decimal(value) * 1000000000000000000))
        if value.endswith("t"):
            if decimals is None:
                raise ValueError("t without decimals")
            value = value.removesuffix("t")
            return Wei(int(Decimal(value) * 10**decimals))
        if value.isdigit():
            return Wei(int(value))
        raise ValueError("wrong value " + value)

    raise ValueError(f"value has a wrong type: {type(value)}")


def from_wei(
    value: int,
    unit: str,
    round_ndigits: int | None = None,
    decimals: int | None = None,
) -> Decimal:
    if value == 0:
        return Decimal(0)

    is_negative = value < 0
    if unit.lower() == "eth":
        unit = "ether"

    if unit.lower() == "t":
        if decimals is None:
            raise ValueError("t without decimals")
        with localcontext() as ctx:
            ctx.prec = 999
            res = Decimal(value=abs(value), context=ctx) / Decimal(10**decimals)
    else:
        res = cast(Decimal, eth_utils.from_wei(abs(value), unit))
    if round_ndigits is not None:
        res = round(res, ndigits=round_ndigits)
    return -1 * res if is_negative else res


def from_wei_str(
    value: int,
    unit: str,
    round_ndigits: int | None = None,
    print_unit_name: bool = True,
    decimals: int | None = None,
) -> str:
    res = format(from_wei(value, unit, round_ndigits, decimals=decimals), "f")
    if unit == "ether":
        unit = "eth"
    if print_unit_name:
        res += unit
    return res


def from_token_wei_str(value: int, decimals: int, symbol: str = "", round_ndigits: int | None = None) -> str:
    res = value / 10**decimals
    if round_ndigits is not None:
        res = round(res, ndigits=round_ndigits)
    if symbol:
        res = f"{res} {symbol}"
    return str(res)


def to_wei_token(value: str | int | Decimal, symbol: str, decimals: int) -> int:
    if isinstance(value, int):
        return value
    if isinstance(value, Decimal):
        if value != value.to_integral_value():
            raise ValueError(f"value must be integral number: {value}")
        return int(value)
    if isinstance(value, str):
        value = value.lower().replace(" ", "").strip()
        if value.isdigit():
            return int(value)
        try:
            return int(Decimal(value.replace(symbol.lower(), "").strip()) * (10**decimals))
        except Exception as e:
            raise ValueError from e
    else:
        raise TypeError(f"value has a wrong type: {type(value)}")


def to_checksum_address(address: str) -> str:
    return Web3.to_checksum_address(address)


def hex_to_bytes(data: str) -> bytes:
    return eth_utils.to_bytes(hexstr=HexStr(data))


def get_chain_name(chain_id: int | str) -> str:
    chain_id = str(chain_id)
    if chain_id == "1":
        return "mainnet"
    if chain_id == "3":
        return "ropsten"
    if chain_id == "5":
        return "goerli"
    return chain_id


def to_human_readable_tx(tx: dict[str, Any] | BaseModel) -> dict[str, object]:
    if isinstance(tx, BaseModel):
        tx = tx.model_dump()
    tx["human_readable"] = {}
    tx["human_readable"]["gas_price"] = str(tx["gas_price"] / 10**9) + " gwei"
    tx["human_readable"]["value"] = str(tx["value"] / 10**18) + " ether"
    tx["human_readable"]["gas"] = number_with_separator(tx["gas"])
    if tx.get("chain_id") is not None:
        tx["human_readable"]["chain_id"] = get_chain_name(tx["chain_id"])

    return tx


def truncate_hex_str(hex_str: str, digits: int = 4, replace_str: str = "...") -> str:
    if not hex_str.startswith("0x") and not hex_str.startswith("0X"):
        raise ValueError("truncate_hex_str: hex_str must start with 0x")
    if digits <= 0:
        raise ValueError("truncate_hex_str: digits must be more than zero")
    hex_str = hex_str.removeprefix("0x").removeprefix("0X")
    if digits * 2 >= len(hex_str):
        raise ValueError("truncate_hex_str: digits is too large")
    return "0x" + hex_str[:digits] + replace_str + hex_str[-1 * digits :]


def log_topic_to_address(topic: HexBytes | str) -> str:
    result = topic.hex()[-40:] if isinstance(topic, HexBytes) else topic[-40:]
    if not result.startswith("0x"):
        result = f"0x{result}"
    return result


def get_w3(rpc_url: str, timeout: int | None = None, proxy: str | None = None) -> Web3:
    request_kwargs: dict[str, object] = {"timeout": timeout}
    if proxy:
        request_kwargs["proxies"] = {"http": proxy, "https": proxy}
    return Web3(Web3.HTTPProvider(rpc_url, request_kwargs=request_kwargs))


def name_network(chain_id: int) -> str:
    match chain_id:
        case 1:
            return "Ethereum Mainnet"
        case 5:
            return "Goerli"
        case 10:
            return "OP Mainnet"
        case 280:
            return "zkSync Era Testnet"
        case 324:
            return "zkSync Era Mainnet"
        case 420:
            return "Optimism Goerli Testnet"
        case 42161:
            return "Arbitrum One"
        case 43113:
            return "Avalanche Fuji Testnet"
        case 43114:
            return "Avalanche C-Chain"
        case 421613:
            return "Arbitrum Goerli"
        case _:
            return ""


def hex_str_to_int(value: str) -> Result[int]:
    try:
        return Ok(int(value, 16))
    except Exception:
        return Err(f"can't convert to int: {value}")


def random_node(nodes: Nodes, remove_slash: bool = True) -> str:
    node = cast(str, random_choice(nodes))
    if remove_slash and node.endswith("/"):
        node = node.removesuffix("/")
    return node


def random_proxy(proxies: Proxies) -> str | None:
    return random_str_choice(proxies)


def to_hex(data: bytes | int | bool) -> str:
    return Web3.to_hex(data)
