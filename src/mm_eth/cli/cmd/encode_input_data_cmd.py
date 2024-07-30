import json

from mm_std import print_plain

from mm_eth import abi


def run(function_signature: str, args_str: str) -> None:
    args_str = args_str.replace("'", '"')
    print_plain(abi.encode_function_input_by_signature(function_signature, json.loads(args_str)))
