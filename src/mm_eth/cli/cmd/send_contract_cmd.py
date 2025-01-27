import json
import sys
import time
from pathlib import Path
from typing import Self

import mm_crypto_utils
from loguru import logger
from mm_crypto_utils import AddressToPrivate
from mm_std import BaseConfig, Err, Ok, str_to_list, utc_now
from pydantic import Field, StrictStr, field_validator, model_validator

from mm_eth import abi, rpc
from mm_eth.account import get_address, private_to_address
from mm_eth.cli import calcs, cli_utils, print_helpers, rpc_helpers, validators
from mm_eth.tx import sign_tx
from mm_eth.utils import from_wei_str


class Config(BaseConfig):
    contract_address: str
    function_signature: str
    function_args: StrictStr = "[]"
    nodes: list[StrictStr]
    chain_id: int
    private_keys: AddressToPrivate = Field(default_factory=AddressToPrivate)
    private_keys_file: Path | None = None
    max_fee_per_gas: str
    max_fee_per_gas_limit: str | None = None
    max_priority_fee_per_gas: str
    value: str | None = None
    gas: str
    from_addresses: list[str]
    delay: str | None = None  # in seconds
    round_ndigits: int = 5
    log_debug: Path | None = None
    log_info: Path | None = None

    @field_validator("log_debug", "log_info", mode="before")
    def log_validator(cls, v: str | None) -> str | None:
        return validators.log_validator(v)

    @field_validator("nodes", "from_addresses", mode="before")
    def list_validator(cls, v: str | list[str] | None) -> list[str]:
        return validators.nodes_validator(v)

    @field_validator("from_addresses", mode="before")
    def from_addresses_validator(cls, v: str | list[str] | None) -> list[str]:
        return str_to_list(v, remove_comments=True, lower=True)

    @field_validator("private_keys", mode="before")
    def private_keys_validator(cls, v: str | list[str] | None) -> AddressToPrivate:
        if v is None:
            return AddressToPrivate()
        private_keys = str_to_list(v, unique=True, remove_comments=True) if isinstance(v, str) else v
        return AddressToPrivate.from_list(private_keys, get_address, address_lowercase=True)

    # noinspection DuplicatedCode
    @model_validator(mode="after")
    def final_validator(self) -> Self:
        # load private keys from file
        if self.private_keys_file:
            self.private_keys.update(AddressToPrivate.from_file(self.private_keys_file, private_to_address))

        # check that from_addresses is not empty
        if not self.from_addresses:
            raise ValueError("from_addresses is empty")

        # max_fee_per_gas
        if not validators.is_valid_calc_var_wei_value(self.max_fee_per_gas, "base"):
            raise ValueError(f"wrong max_fee_per_gas: {self.max_fee_per_gas}")

        # max_fee_per_gas_limit
        if not validators.is_valid_calc_var_wei_value(self.max_fee_per_gas_limit, "base"):
            raise ValueError(f"wrong max_fee_per_gas_limit: {self.max_fee_per_gas_limit}")

        # max_priority_fee_per_gas
        if not validators.is_valid_calc_var_wei_value(self.max_priority_fee_per_gas):
            raise ValueError(f"wrong max_priority_fee_per_gas: {self.max_priority_fee_per_gas}")

        # value
        if self.value is not None and not validators.is_valid_calc_var_wei_value(self.value, "balance"):
            raise ValueError(f"wrong value: {self.value}")

        # gas
        if not validators.is_valid_calc_var_wei_value(self.gas, "estimate"):
            raise ValueError(f"wrong gas: {self.gas}")

        # delay
        if not validators.is_valid_calc_decimal_value(self.delay):
            raise ValueError(f"wrong delay: {self.delay}")

        # function_args
        if not validators.is_valid_calc_function_args(self.function_args):
            raise ValueError(f"wrong function_args: {self.function_args}")

        return self


# noinspection DuplicatedCode
def run(
    config_path: str,
    *,
    print_balances: bool,
    print_config: bool,
    debug: bool,
    no_receipt: bool,
    emulate: bool,
) -> None:
    config = Config.read_config_or_exit(config_path)
    cli_utils.print_config_and_exit(print_config, config, {"private_key"})

    mm_crypto_utils.init_logger(debug, config.log_debug, config.log_info)

    rpc_helpers.check_nodes_for_chain_id(config.nodes, config.chain_id)

    if print_balances:
        print_helpers.print_balances(config.nodes, config.from_addresses, round_ndigits=config.round_ndigits)
        sys.exit(0)

    _run_transfers(config, no_receipt=no_receipt, emulate=emulate)


# noinspection DuplicatedCode
def _run_transfers(config: Config, *, no_receipt: bool, emulate: bool) -> None:
    logger.info(f"started at {utc_now()} UTC")
    logger.debug(f"config={config.model_dump(exclude={'private_keys'}) | {'version': cli_utils.get_version()}}")
    cli_utils.check_private_keys(config.from_addresses, config.private_keys)
    for i, from_address in enumerate(config.from_addresses):
        _transfer(from_address=from_address, config=config, no_receipt=no_receipt, emulate=emulate)
        if not emulate and config.delay is not None and i < len(config.from_addresses) - 1:
            delay_value = mm_crypto_utils.calc_decimal_value(config.delay)
            logger.debug(f"delay {delay_value} seconds")
            time.sleep(float(delay_value))
    logger.info(f"finished at {utc_now()} UTC")


# noinspection DuplicatedCode
def _transfer(*, from_address: str, config: Config, no_receipt: bool, emulate: bool) -> None:
    log_prefix = f"{from_address}"
    # get nonce
    nonce = rpc_helpers.get_nonce(config.nodes, from_address, log_prefix)
    if nonce is None:
        return

    # get max_fee_per_gas
    max_fee_per_gas = rpc_helpers.calc_max_fee_per_gas(config.nodes, config.max_fee_per_gas, log_prefix)
    if max_fee_per_gas is None:
        return

    # check max_fee_per_gas_limit
    if rpc_helpers.is_max_fee_per_gas_limit_exceeded(max_fee_per_gas, config.max_fee_per_gas_limit, log_prefix):
        return

    max_priority_fee_per_gas = calcs.calc_var_wei_value(config.max_priority_fee_per_gas)

    # data
    function_args = calcs.calc_function_args(config.function_args).replace("'", '"')
    data = abi.encode_function_input_by_signature(config.function_signature, json.loads(function_args))

    # get gas
    gas = rpc_helpers.calc_gas(
        nodes=config.nodes,
        gas=config.gas,
        from_address=from_address,
        to_address=config.contract_address,
        value=None,
        data=data,
        log_prefix=log_prefix,
    )
    if gas is None:
        return

    # get value
    value = None
    if config.value is not None:
        value = rpc_helpers.calc_eth_value(
            nodes=config.nodes,
            value_str=config.value,
            address=from_address,
            gas=gas,
            max_fee_per_gas=max_fee_per_gas,
            log_prefix=log_prefix,
        )
        if value is None:
            return

    tx_params = {
        "nonce": nonce,
        "max_fee_per_gas": max_fee_per_gas,
        "max_priority_fee_per_gas": max_priority_fee_per_gas,
        "gas": gas,
        "value": value,
        "to": config.contract_address,
        "chain_id": config.chain_id,
    }

    # emulate?
    if emulate:
        msg = f"{log_prefix}: emulate,"
        if value is not None:
            msg += f" value={from_wei_str(value, 'eth', config.round_ndigits)},"
        msg += f" max_fee_per_gas={from_wei_str(max_fee_per_gas, 'gwei', config.round_ndigits)},"
        msg += f" max_priority_fee_per_gas={from_wei_str(max_priority_fee_per_gas, 'gwei', config.round_ndigits)},"
        msg += f" gas={gas}"
        logger.info(msg)
        return

    logger.debug(f"{log_prefix}: tx_params={tx_params}")
    signed_tx = sign_tx(
        nonce=nonce,
        max_fee_per_gas=max_fee_per_gas,
        max_priority_fee_per_gas=max_priority_fee_per_gas,
        gas=gas,
        private_key=config.private_keys[from_address],
        chain_id=config.chain_id,
        value=value,
        data=data,
        to=config.contract_address,
    )
    res = rpc.eth_send_raw_transaction(config.nodes, signed_tx.raw_tx, attempts=5)
    if isinstance(res, Err):
        logger.info(f"{log_prefix}: send_error: {res.err}")
        return
    tx_hash = res.ok

    if no_receipt:
        msg = f"{log_prefix}: tx_hash={tx_hash}"
        logger.info(msg)
    else:
        logger.debug(f"{log_prefix}: tx_hash={tx_hash}, wait receipt")
        while True:  # TODO: infinite loop if receipt_res is err
            receipt_res = rpc.get_tx_status(config.nodes, tx_hash)
            if isinstance(receipt_res, Ok):
                status = "OK" if receipt_res.ok == 1 else "FAIL"
                msg = f"{log_prefix}: tx_hash={tx_hash}, status={status}"
                logger.info(msg)
                break
            time.sleep(1)
