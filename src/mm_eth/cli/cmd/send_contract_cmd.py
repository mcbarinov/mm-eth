import json
import sys
import time
from pathlib import Path
from typing import Self

from loguru import logger
from mm_std import BaseConfig, Err, Ok, print_json, str_to_list, utc_now
from pydantic import Field, StrictStr, field_validator, model_validator

from mm_eth import abi, rpc
from mm_eth.account import create_private_keys_dict, private_to_address
from mm_eth.cli import calcs, cli_utils, print_helpers, rpc_helpers, validators
from mm_eth.tx import sign_tx
from mm_eth.utils import from_wei_str


class Config(BaseConfig):
    contract_address: str
    function_signature: str
    function_args: StrictStr = "[]"
    nodes: list[StrictStr]
    chain_id: int
    private_keys: dict[str, str] = Field(default_factory=dict)
    private_keys_file: str | None = None
    max_fee_per_gas: str
    max_fee_per_gas_limit: str | None = None
    max_priority_fee_per_gas: str
    value: str | None = None
    gas: str
    from_addresses: list[str]
    delay: str | None = None  # in seconds
    round_ndigits: int = 5
    log_debug: str | None = None
    log_info: str | None = None

    @field_validator("log_debug", "log_info", mode="before")
    @classmethod
    def log_validator(cls, v: str | None) -> str | None:
        return validators.log_validator(v)

    @field_validator("nodes", "from_addresses", mode="before")
    @classmethod
    def list_validator(cls, v: str | list[str] | None) -> list[str]:
        return validators.nodes_validator(v)

    @field_validator("from_addresses", mode="before")
    @classmethod
    def from_addresses_validator(cls, v: str | list[str] | None) -> list[str]:
        return str_to_list(v, remove_comments=True, lower=True)

    @field_validator("private_keys", mode="before")
    @classmethod
    def private_keys_validator(cls, v: str | list[str] | None) -> dict[str, str]:
        if v is None:
            return {}
        if isinstance(v, str):
            return create_private_keys_dict(str_to_list(v, unique=True, remove_comments=True))
        return create_private_keys_dict(v)

    # noinspection DuplicatedCode
    @model_validator(mode="after")
    def final_validator(self) -> Self:
        # load private keys from file
        if self.private_keys_file:
            file = Path(self.private_keys_file).expanduser()
            if not file.is_file():
                raise ValueError("can't read private_keys_file")
            for line in file.read_text().strip().split("\n"):
                line = line.strip()  # noqa: PLW2901
                address = private_to_address(line)
                if address is None:
                    raise ValueError("there is not a private key in private_keys_file")
                self.private_keys[address.lower()] = line

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
    config = cli_utils.read_config(Config, Path(config_path))
    if print_config:
        print_json(config.model_dump(exclude={"private_key"}))
        sys.exit(0)

    cli_utils.init_logger(debug, config.log_debug, config.log_info)
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
            delay_value = calcs.calc_decimal_value(config.delay)
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
        while True:
            receipt_res = rpc.get_tx_status(config.nodes, tx_hash)
            if isinstance(receipt_res, Ok):
                status = "OK" if receipt_res.ok == 1 else "FAIL"
                msg = f"{log_prefix}: tx_hash={tx_hash}, status={status}"
                logger.info(msg)
                break
            time.sleep(1)
