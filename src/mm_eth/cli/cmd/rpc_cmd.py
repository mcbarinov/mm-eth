import json
from typing import cast

from mm_std import fatal, hr, print_console, str_starts_with_any
from rich import print_json

from mm_eth.cli.cli_utils import public_rpc_url


def run(rpc_url: str, method: str, params: str, hex2dec: bool) -> None:
    rpc_url = public_rpc_url(rpc_url)
    if not method:
        return list_all_methods()
    if not str_starts_with_any(rpc_url, ["http://", "https://"]):
        fatal(f"invalid rpc_url: {rpc_url}")
    params = params.replace("'", '"')
    data = {"jsonrpc": "2.0", "method": method, "params": parse_method_params(method, params), "id": 1}
    res = hr(rpc_url, method="POST", params=data, json_params=True)
    if res.json:
        print_json(data=res.json)
        result_value: str = res.json.get("result", "")
        if hex2dec and result_value.startswith(("0x", "0X")):
            print_console("hex2dec", int(result_value, 16))
    else:
        fatal(str(res))


def parse_method_params(method: str, params_str: str) -> list[object]:
    params = json.loads(params_str) if params_str.startswith("[") else params_str.split()
    if method in ["eth_getBalance", "eth_getTransactionCount", "eth_getCode"] and len(params) == 1:
        params.append("latest")
    return cast(list[object], params)


def list_all_methods() -> None:
    all_methods = """
web3_clientVersion
web3_sha3
net_version
net_listening
net_peerCount
eth_protocolVersion
eth_syncing
eth_chainId
eth_gasPrice
eth_accounts
eth_blockNumber
eth_getBalance
eth_getStorageAt
eth_getTransactionCount
eth_getBlockTransactionCountByHash
eth_getBlockTransactionCountByNumber
eth_getUncleCountByBlockHash
eth_getUncleCountByBlockNumber
eth_getCode
eth_sign
eth_signTransaction
eth_sendTransaction
eth_sendRawTransaction
eth_call
eth_estimateGas
eth_getBlockByHash
eth_getBlockByNumber
eth_getTransactionByHash
eth_getTransactionByBlockHashAndIndex
eth_getTransactionByBlockNumberAndIndex
eth_getTransactionReceipt
eth_getUncleByBlockHashAndIndex
eth_getUncleByBlockNumberAndIndex
eth_newFilter
eth_newBlockFilter
eth_newPendingTransactionFilter
eth_uninstallFilter
eth_getFilterChanges
eth_getFilterLogs
eth_getLogs
    """.strip()
    print_console(all_methods)
