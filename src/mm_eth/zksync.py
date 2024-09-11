import json
import pkgutil
from typing import cast

from eth_typing import ABI, ChecksumAddress, HexStr
from hexbytes import HexBytes
from mm_std import Err, Ok, Result
from pydantic import BaseModel, Field
from web3 import Web3
from web3.types import Nonce, TxParams, Wei

from mm_eth import abi, rpc
from mm_eth.rpc import rpc_call
from mm_eth.types import Nodes, Proxies
from mm_eth.utils import hex_str_to_int

L2_ETH_TOKEN_ADDRESS = Web3.to_checksum_address("0x000000000000000000000000000000000000800a")


class BridgeContracts(BaseModel):
    l1_erc20_Default_bridge: str = Field(..., alias="l1Erc20DefaultBridge")
    l2_erc20_Default_bridge: str = Field(..., alias="l2Erc20DefaultBridge")


def zks_get_bridge_contracts(
    rpc_urls: Nodes,
    timeout: int = 10,
    proxies: Proxies = None,
    attempts: int = 1,
) -> Result[BridgeContracts]:
    res = rpc_call(
        nodes=rpc_urls,
        method="zks_getBridgeContracts",
        params=[],
        timeout=timeout,
        proxies=proxies,
        attempts=attempts,
    )
    if isinstance(res, Err):
        return res

    try:
        return Ok(BridgeContracts(**res.ok), data=res.data)
    except Exception as e:
        return Err(f"exception: {e}", data=res.data)


def zks_get_main_contract(
    rpc_urls: Nodes,
    timeout: int = 10,
    proxies: Proxies = None,
    attempts: int = 1,
) -> Result[str]:
    return rpc_call(
        nodes=rpc_urls,
        method="zks_getMainContract",
        params=[],
        timeout=timeout,
        proxies=proxies,
        attempts=attempts,
    )


def zks_estimate_gas_l1_to_l2(
    rpc_urls: Nodes,
    timeout: int = 10,
    proxies: Proxies = None,
    attempts: int = 1,
) -> Result[int]:
    return rpc_call(
        nodes=rpc_urls,
        method="zks_estimateGasL1ToL2",
        params=[
            [
                {
                    "from": "0x1111111111111111111111111111111111111111",
                    "to": "0x2222222222222222222222222222222222222222",
                    "data": "0xffffffff",
                },
            ],
        ],
        timeout=timeout,
        proxies=proxies,
        attempts=attempts,
    ).and_then(hex_str_to_int)


def zksync_contract_abi() -> ABI:
    data = pkgutil.get_data(__name__, "abi/zksync.json")
    if data is None:
        raise RuntimeError("can't read abi/zksync.json")
    return cast(ABI, json.loads(data.decode()))


def get_l2_transactio_base_cost(
    eth_rpc: str,
    contract_address: ChecksumAddress,
    gas_price: Wei,
    l2_gas_limit: int = 10000000,
    l2_gas_per_pubdata_byte_limit: int = 800,
) -> Result[Wei]:
    w3 = Web3(Web3.HTTPProvider(eth_rpc))
    try:
        contract = w3.eth.contract(address=contract_address, abi=zksync_contract_abi())
        res = contract.functions.l2TransactionBaseCost(gas_price, l2_gas_limit, l2_gas_per_pubdata_byte_limit).call()
        return Ok(Wei(res))
    except Exception as e:
        return Err(str(e))


def deposit(
    *,
    eth_rpc: str,
    contract_address: ChecksumAddress,
    wallet_address: ChecksumAddress,
    private_key: str,
    gas_price: Wei,
    value: Wei,
    l2_gas_limit: int = 1_300_000,
    l2_gas_per_pubdata_byte_limit: int = 800,
    gas: int = 150096,
    nonce: Nonce | None = None,
) -> Result[str]:
    w3 = Web3(Web3.HTTPProvider(eth_rpc))
    try:
        # get nonce
        if nonce is None:
            res_nonce = rpc.eth_get_transaction_count(eth_rpc, wallet_address)
            if isinstance(res_nonce, Err):
                return res_nonce

            nonce = Nonce(res_nonce.ok)

        # get base_cost
        res = get_l2_transactio_base_cost(eth_rpc, contract_address, gas_price, l2_gas_limit, l2_gas_per_pubdata_byte_limit)
        if isinstance(res, Err):
            return res
        base_cost = Wei(res.ok)

        contract_address_l2 = wallet_address
        l2_value = value
        calldata = b""
        factory_deps = []  # type: ignore[var-annotated]
        refund_recipient = wallet_address

        contract = w3.eth.contract(address=contract_address, abi=zksync_contract_abi())
        function_call = contract.functions.requestL2Transaction(
            contract_address_l2,
            l2_value,
            calldata,
            l2_gas_limit,
            l2_gas_per_pubdata_byte_limit,
            factory_deps,
            refund_recipient,
        )

        transaction_data = function_call.build_transaction(
            {"from": wallet_address, "gas": gas, "gasPrice": gas_price, "nonce": nonce, "value": Wei(value + base_cost)},
        )
        signed_transaction = w3.eth.account.sign_transaction(transaction_data, private_key)
        txn = w3.eth.send_raw_transaction(signed_transaction.rawTransaction)
        return Ok(str(txn))
    except Exception as e:
        return Err(f"exception: {e}")


def withdraw(
    *,
    zksync_rpc: str,
    wallet_address: ChecksumAddress,
    private_key: str,
    value: Wei,
    chain_id: int,
) -> Result[HexBytes]:
    try:
        w3 = Web3(Web3.HTTPProvider(zksync_rpc))

        # get nonce
        nonce = w3.eth.get_transaction_count(wallet_address)

        input_data = abi.encode_function_signature("withdraw(address)") + abi.encode_data(
            ["address"],
            [wallet_address],
        ).removeprefix("0x")

        transaction_data: TxParams = {
            "from": wallet_address,
            "to": L2_ETH_TOKEN_ADDRESS,
            "nonce": nonce,
            "data": HexStr(input_data),
            "value": value,
            "chainId": chain_id,
        }
        gas = w3.eth.estimate_gas(transaction_data)
        transaction_data["gas"] = gas
        gas_price = w3.eth.gas_price
        transaction_data["gasPrice"] = gas_price
        signed_transaction = w3.eth.account.sign_transaction(transaction_data, private_key)
        txn = w3.eth.send_raw_transaction(signed_transaction.rawTransaction)
        return Ok(txn)

    except Exception as e:
        return Err(f"exception: {e}")
