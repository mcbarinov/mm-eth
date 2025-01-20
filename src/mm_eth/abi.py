import string
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, cast

import eth_abi
import eth_utils
import pydash
from eth_typing import ABI, ABIFunction, HexStr
from pydantic import BaseModel
from web3 import Web3
from web3.auto import w3

from mm_eth.utils import hex_to_bytes


@dataclass
class NameTypeValue:
    name: str
    type: str
    value: Any


class FunctionInput(BaseModel):
    function_abi: ABIFunction
    params: dict[str, Any]

    def decode_params_bytes(self) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for k, v in self.params.items():
            if isinstance(v, bytes):
                try:
                    str_value = eth_utils.to_text(v)
                except UnicodeDecodeError:
                    str_value = eth_utils.to_hex(v)
                result[k] = "".join(filter(lambda x: x in string.printable, str_value))
            else:
                result[k] = v
        return result

    def function_signature(self) -> str:
        inputs = [i["name"] for i in self.function_abi["inputs"]]
        return self.function_abi["name"] + f"({','.join(inputs)})"

    def to_list(self, decode_bytes: bool = False) -> list[NameTypeValue]:
        result = []
        for param in self.function_abi["inputs"]:
            name = param["name"]
            type_ = param["type"]
            value = self.params[name]
            if decode_bytes and isinstance(value, bytes):
                try:
                    value = eth_utils.to_text(value)
                except UnicodeDecodeError:
                    value = eth_utils.to_hex(value)
            result.append(NameTypeValue(name, type_, value))
        return result


def decode_function_input(contract_abi: ABI, tx_input: str) -> FunctionInput:
    contract = w3.eth.contract(abi=contract_abi)
    func, params = contract.decode_function_input(HexStr(tx_input))
    return FunctionInput(function_abi=func.abi, params=params)


def get_function_abi(contr_abi: ABI, fn_name: str) -> ABIFunction:
    abi = pydash.find(contr_abi, lambda x: x.get("name", None) == fn_name and x.get("type", None) == "function")  # type: ignore[call-overload, attr-defined]
    if not abi:
        raise ValueError("can't find abi for function: " + fn_name)
    return cast(ABIFunction, abi)


def encode_function_input_by_abi(abi: ABI | ABIFunction, fn_name: str, args: list[Any]) -> HexStr:
    # if abi is contract_abi, get function_abi
    if isinstance(abi, Sequence):
        abi = get_function_abi(abi, fn_name)
    abi = cast(ABIFunction, abi)

    # need update all address values to checkSum version
    processed_args = []
    for idx, arg in enumerate(abi["inputs"]):
        if arg["type"] == "address":
            processed_args.append(eth_utils.to_checksum_address(args[idx]))
        else:
            processed_args.append(args[idx])

    return Web3().eth.contract(abi=[abi]).encode_abi(abi_element_identifier=fn_name, args=processed_args)  # type: ignore[no-any-return]


def encode_function_input_by_signature(func_signature: str, args: list[Any]) -> HexStr:
    if not func_signature.endswith(")"):
        raise ValueError(f"wrong func_signature={func_signature}. example: func1(uint256,address)")
    func_signature = func_signature.removesuffix(")")
    arr = func_signature.split("(")
    if len(arr) != 2:
        raise ValueError(f"wrong func_signature={func_signature}. example: func1(uint256,address)")
    func_name = arr[0]
    arg_types = [t.strip() for t in arr[1].split(",") if t.strip()]
    func_abi: ABIFunction = {
        "name": func_name,
        "type": "function",
        "inputs": [{"type": t} for t in arg_types],  # type: ignore[typeddict-item]
    }
    return encode_function_input_by_abi(func_abi, func_name, args)


def encode_function_signature(func_name_with_types: str) -> HexStr:
    """input example 'transfer(address,uint256)'"""
    return HexStr(eth_utils.to_hex(Web3.keccak(text=func_name_with_types))[0:10])


def decode_data(types: list[str], data: str) -> tuple[Any, ...]:
    return eth_abi.decode(types, hex_to_bytes(data))


def encode_data(types: list[str], args: list[Any]) -> str:
    return eth_utils.to_hex(eth_abi.encode(types, args))


def parse_function_signatures(contract_abi: ABI) -> dict[str, str]:
    """returns dict, key: function_name_and_types, value: 4bytes signature"""
    result: dict[str, str] = {}
    for item in contract_abi:
        if item.get("type", None) == "function":
            function_name = item["name"]  # type: ignore[typeddict-item]
            types = ",".join([i["type"] for i in item["inputs"]])  # type: ignore[typeddict-item]
            function_name_and_types = f"{function_name}({types})"
            result[function_name_and_types] = encode_function_signature(function_name_and_types)
    return result
