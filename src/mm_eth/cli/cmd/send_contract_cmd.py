import json
import sys
import time
from pathlib import Path
from typing import Annotated, Self

import mm_crypto_utils
from loguru import logger
from mm_crypto_utils import AddressToPrivate
from mm_std import BaseConfig, Err, Ok, utc_now
from pydantic import AfterValidator, BeforeValidator, StrictStr, model_validator

from mm_eth import abi, rpc
from mm_eth.cli import calcs, cli_utils, print_helpers, rpc_helpers, validators
from mm_eth.cli.calcs import calc_eth_expression
from mm_eth.cli.cli_utils import BaseConfigParams
from mm_eth.cli.validators import Validators
from mm_eth.tx import sign_tx
from mm_eth.utils import from_wei_str


class Config(BaseConfig):
    from_addresses: Annotated[list[str], BeforeValidator(Validators.eth_addresses(unique=True))]
    contract_address: Annotated[str, BeforeValidator(Validators.eth_address())]
    function_signature: str
    function_args: StrictStr = "[]"
    nodes: Annotated[list[str], BeforeValidator(Validators.nodes())]
    chain_id: int
    private_keys: Annotated[AddressToPrivate, BeforeValidator(Validators.eth_private_keys())]
    max_fee: Annotated[str, AfterValidator(Validators.valid_eth_expression("base_fee"))]
    priority_fee: Annotated[str, AfterValidator(Validators.valid_eth_expression())]
    max_fee_limit: Annotated[str | None, AfterValidator(Validators.valid_eth_expression())] = None
    value: Annotated[str, AfterValidator(Validators.valid_eth_expression("balance"))]  # eth value
    gas: Annotated[str, AfterValidator(Validators.valid_eth_expression("estimate"))]
    delay: Annotated[str | None, AfterValidator(Validators.valid_calc_decimal_value())] = None  # in seconds
    round_ndigits: int = 5
    log_debug: Annotated[Path | None, BeforeValidator(Validators.log_file())] = None
    log_info: Annotated[Path | None, BeforeValidator(Validators.log_file())] = None

    # noinspection DuplicatedCode
    @model_validator(mode="after")
    def final_validator(self) -> Self:
        # check all private keys exist
        if not self.private_keys.contains_all_addresses(self.from_addresses):
            raise ValueError("private keys are not set for all addresses")

        # check that from_addresses is not empty
        if not self.from_addresses:
            raise ValueError("from_addresses is empty")

        # function_args
        if not validators.is_valid_calc_function_args(self.function_args):
            raise ValueError(f"wrong function_args: {self.function_args}")

        return self


class SendContractCmdParams(BaseConfigParams):
    print_balances: bool
    debug: bool
    no_receipt: bool
    emulate: bool


# noinspection DuplicatedCode
def run(cli_params: SendContractCmdParams) -> None:
    config = Config.read_toml_config_or_exit(cli_params.config_path)
    if cli_params.print_config:
        config.print_and_exit({"private_key"})

    mm_crypto_utils.init_logger(cli_params.debug, config.log_debug, config.log_info)

    rpc_helpers.check_nodes_for_chain_id(config.nodes, config.chain_id)

    if cli_params.print_balances:
        print_helpers.print_balances(config.nodes, config.from_addresses, round_ndigits=config.round_ndigits)
        sys.exit(0)

    _run_transfers(config, cli_params)


# noinspection DuplicatedCode
def _run_transfers(config: Config, cli_params: SendContractCmdParams) -> None:
    logger.info(f"started at {utc_now()} UTC")
    logger.debug(f"config={config.model_dump(exclude={'private_keys'}) | {'version': cli_utils.get_version()}}")
    for i, from_address in enumerate(config.from_addresses):
        _transfer(from_address, config, cli_params)
        if not cli_params.emulate and config.delay is not None and i < len(config.from_addresses) - 1:
            delay_value = mm_crypto_utils.calc_decimal_value(config.delay)
            logger.debug(f"delay {delay_value} seconds")
            time.sleep(float(delay_value))
    logger.info(f"finished at {utc_now()} UTC")


# noinspection DuplicatedCode
def _transfer(from_address: str, config: Config, cli_params: SendContractCmdParams) -> None:
    log_prefix = f"{from_address}"
    # get nonce
    nonce = rpc_helpers.get_nonce(config.nodes, from_address, log_prefix)
    if nonce is None:
        return

    # get max_fee
    max_fee = rpc_helpers.calc_max_fee(config.nodes, config.max_fee, log_prefix)
    if max_fee is None:
        return

    # check max_fee_limit
    if rpc_helpers.is_max_fee_limit_exceeded(max_fee, config.max_fee_limit, log_prefix):
        return

    priority_fee = calc_eth_expression(config.priority_fee)

    # data
    function_args = calcs.calc_function_args(config.function_args).replace("'", '"')
    data = abi.encode_function_input_by_signature(config.function_signature, json.loads(function_args))

    # get gas
    gas = rpc_helpers.calc_gas(
        nodes=config.nodes,
        gas_expression=config.gas,
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
        value = rpc_helpers.calc_eth_value_for_address(
            nodes=config.nodes,
            value_expression=config.value,
            address=from_address,
            gas=gas,
            max_fee=max_fee,
            log_prefix=log_prefix,
        )
        if value is None:
            return

    # emulate?
    if cli_params.emulate:
        msg = f"{log_prefix}: emulate,"
        if value is not None:
            msg += f" value={from_wei_str(value, 'eth', config.round_ndigits)},"
        msg += f" max_fee={from_wei_str(max_fee, 'gwei', config.round_ndigits)},"
        msg += f" priority_fee={from_wei_str(priority_fee, 'gwei', config.round_ndigits)},"
        msg += f" gas={gas}, "
        msg += f" data={data}"
        logger.info(msg)
        return

    debug_tx_params = {
        "nonce": nonce,
        "max_fee": max_fee,
        "priority_fee": priority_fee,
        "gas": gas,
        "value": value,
        "data": data,
        "to": config.contract_address,
        "chain_id": config.chain_id,
    }
    logger.debug(f"{log_prefix}: tx_params={debug_tx_params}")
    signed_tx = sign_tx(
        nonce=nonce,
        max_fee_per_gas=max_fee,
        max_priority_fee_per_gas=priority_fee,
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

    if cli_params.no_receipt:
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
