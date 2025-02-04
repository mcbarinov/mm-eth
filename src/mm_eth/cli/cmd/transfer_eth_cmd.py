import sys
import time
from pathlib import Path
from typing import Annotated, Self

import mm_crypto_utils
from loguru import logger
from mm_crypto_utils import AddressToPrivate, TxRoute
from mm_std import BaseConfig, Err, Ok, utc_now
from pydantic import AfterValidator, BeforeValidator, model_validator

from mm_eth import rpc
from mm_eth.cli import cli_utils, print_helpers, rpc_helpers
from mm_eth.cli.calcs import calc_eth_expression
from mm_eth.cli.cli_utils import BaseConfigParams
from mm_eth.cli.validators import Validators as Validators
from mm_eth.tx import sign_tx
from mm_eth.utils import from_wei_str


# noinspection DuplicatedCode
class Config(BaseConfig):
    nodes: Annotated[list[str], BeforeValidator(Validators.nodes())]
    chain_id: int
    routes: Annotated[list[TxRoute], BeforeValidator(Validators.eth_routes())]
    private_keys: Annotated[AddressToPrivate, BeforeValidator(Validators.eth_private_keys())]
    max_fee: Annotated[str, AfterValidator(Validators.valid_eth_expression("base_fee"))]
    priority_fee: Annotated[str, AfterValidator(Validators.valid_eth_expression())]
    max_fee_limit: Annotated[str | None, AfterValidator(Validators.valid_eth_expression())] = None
    value: Annotated[str, AfterValidator(Validators.valid_eth_expression("balance"))]
    value_min_limit: Annotated[str | None, AfterValidator(Validators.valid_eth_expression())] = None
    gas: Annotated[str, AfterValidator(Validators.valid_eth_expression("estimate"))]
    delay: Annotated[str | None, AfterValidator(Validators.valid_calc_decimal_value())] = None  # in seconds
    round_ndigits: int = 5
    log_debug: Annotated[Path | None, AfterValidator(Validators.log_file())] = None
    log_info: Annotated[Path | None, AfterValidator(Validators.log_file())] = None

    @property
    def from_addresses(self) -> list[str]:
        return [r.from_address for r in self.routes]

    @model_validator(mode="after")
    def final_validator(self) -> Self:
        if not self.private_keys.contains_all_addresses(self.from_addresses):
            raise ValueError("private keys are not set for all addresses")

        return self


class TransferEthCmdParams(BaseConfigParams):
    print_balances: bool
    debug: bool
    no_receipt: bool
    emulate: bool


def run(cli_params: TransferEthCmdParams) -> None:
    config = Config.read_toml_config_or_exit(cli_params.config_path)
    if cli_params.print_config_and_exit:
        config.print_and_exit({"private_keys"})

    mm_crypto_utils.init_logger(cli_params.debug, config.log_debug, config.log_info)
    rpc_helpers.check_nodes_for_chain_id(config.nodes, config.chain_id)

    if cli_params.print_balances:
        print_helpers.print_balances(config.nodes, config.from_addresses, round_ndigits=config.round_ndigits)
        sys.exit(0)

    return _run_transfers(config, cli_params)


# noinspection DuplicatedCode
def _run_transfers(config: Config, cli_params: TransferEthCmdParams) -> None:
    logger.info(f"started at {utc_now()} UTC")
    logger.debug(f"config={config.model_dump(exclude={'private_keys'}) | {'version': cli_utils.get_version()}}")
    for i, route in enumerate(config.routes):
        _transfer(route, config, cli_params)
        if not cli_params.emulate and config.delay is not None and i < len(config.routes) - 1:
            delay_value = mm_crypto_utils.calc_decimal_value(config.delay)
            logger.debug(f"delay {delay_value} seconds")
            time.sleep(float(delay_value))
    logger.info(f"finished at {utc_now()} UTC")


# noinspection DuplicatedCode
def _transfer(route: TxRoute, config: Config, cli_params: TransferEthCmdParams) -> None:
    log_prefix = f"{route.from_address}->{route.to_address}"
    # get nonce
    nonce = rpc_helpers.get_nonce(config.nodes, route.from_address, log_prefix)
    if nonce is None:
        return

    # get max_fee
    max_fee = rpc_helpers.calc_max_fee(config.nodes, config.max_fee, log_prefix)
    if max_fee is None:
        return

    # check max_fee_limit
    if rpc_helpers.is_max_fee_limit_exceeded(max_fee, config.max_fee_limit, log_prefix):
        return

    # get gas
    gas = rpc_helpers.calc_gas(
        nodes=config.nodes,
        gas_expression=config.gas,
        from_address=route.from_address,
        to_address=route.to_address,
        value=123,
        log_prefix=log_prefix,
    )
    if gas is None:
        return

    # get value
    value = rpc_helpers.calc_eth_value_for_address(
        nodes=config.nodes,
        value_expression=config.value,
        address=route.from_address,
        gas=gas,
        max_fee=max_fee,
        log_prefix=log_prefix,
    )
    if value is None:
        return

    # value_min_limit
    if config.value_min_limit is not None:
        value_min_limit = calc_eth_expression(config.value_min_limit)
        if value < value_min_limit:
            logger.info(f"{log_prefix}value<value_min_limit, value={from_wei_str(value, 'eth', config.round_ndigits)}")
            return

    priority_fee = calc_eth_expression(config.priority_fee)

    # emulate?
    if cli_params.emulate:
        msg = f"{log_prefix}: emulate, value={from_wei_str(value, 'eth', config.round_ndigits)},"
        msg += f" max_fee={from_wei_str(max_fee, 'gwei', config.round_ndigits)},"
        msg += f" priority_fee={from_wei_str(priority_fee, 'gwei', config.round_ndigits)},"
        msg += f" gas={gas}"
        logger.info(msg)
        return

    debug_tx_params = {
        "nonce": nonce,
        "max_fee": max_fee,
        "priority_fee": priority_fee,
        "gas": gas,
        "value": value,
        "to": route.to_address,
        "chain_id": config.chain_id,
    }
    logger.debug(f"{log_prefix}: tx_params={debug_tx_params}")
    signed_tx = sign_tx(
        nonce=nonce,
        max_fee_per_gas=max_fee,
        max_priority_fee_per_gas=priority_fee,
        gas=gas,
        private_key=config.private_keys[route.from_address],
        chain_id=config.chain_id,
        value=value,
        to=route.to_address,
    )
    res = rpc.eth_send_raw_transaction(config.nodes, signed_tx.raw_tx, attempts=5)
    if isinstance(res, Err):
        logger.info(f"{log_prefix}: send_error: {res.err}")
        return
    tx_hash = res.ok

    if cli_params.no_receipt:
        msg = f"{log_prefix}: tx_hash={tx_hash}, value={from_wei_str(value, 'ether', round_ndigits=config.round_ndigits)}"
        logger.info(msg)
    else:
        logger.debug(f"{log_prefix}: tx_hash={tx_hash}, wait receipt")
        while True:  # TODO: infinite loop if receipt_res is err
            receipt_res = rpc.get_tx_status(config.nodes, tx_hash)
            if isinstance(receipt_res, Ok):
                status = "OK" if receipt_res.ok == 1 else "FAIL"
                msg = f"{log_prefix}: tx_hash={tx_hash}, value={from_wei_str(value, 'ether', round_ndigits=config.round_ndigits)}, status={status}"  # noqa: E501
                logger.info(msg)
                break
            time.sleep(1)
