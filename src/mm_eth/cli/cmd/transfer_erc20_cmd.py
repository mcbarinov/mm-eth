import sys
import time
from pathlib import Path
from typing import Annotated, Self

import mm_crypto_utils
from loguru import logger
from mm_crypto_utils import AddressToPrivate, TxRoute
from mm_std import BaseConfig, Err, Ok, fatal, utc_now
from pydantic import AfterValidator, BeforeValidator, model_validator

from mm_eth import erc20, rpc
from mm_eth.cli import cli_utils, print_helpers, rpc_helpers
from mm_eth.cli.calcs import calc_eth_expression
from mm_eth.cli.cli_utils import BaseConfigParams
from mm_eth.cli.validators import Validators
from mm_eth.utils import from_wei_str


# noinspection DuplicatedCode
class Config(BaseConfig):
    nodes: Annotated[list[str], BeforeValidator(Validators.nodes())]
    chain_id: int
    routes: Annotated[list[TxRoute], BeforeValidator(Validators.eth_routes())]
    private_keys: Annotated[AddressToPrivate, BeforeValidator(Validators.eth_private_keys())]
    token: Annotated[str, AfterValidator(Validators.eth_address())]
    decimals: int
    max_fee: Annotated[str, AfterValidator(Validators.valid_eth_expression("base_fee"))]
    priority_fee: Annotated[str, AfterValidator(Validators.valid_eth_expression())]
    max_fee_limit: Annotated[str | None, AfterValidator(Validators.valid_eth_expression())] = None
    value: Annotated[str, AfterValidator(Validators.valid_token_expression("balance"))]
    value_min_limit: Annotated[str | None, AfterValidator(Validators.valid_token_expression())] = None
    gas: Annotated[str, AfterValidator(Validators.valid_eth_expression("estimate"))]
    delay: Annotated[str | None, AfterValidator(Validators.valid_calc_decimal_value())] = None  # in seconds
    round_ndigits: int = 5
    log_debug: Annotated[Path | None, BeforeValidator(Validators.log_file())] = None
    log_info: Annotated[Path | None, BeforeValidator(Validators.log_file())] = None

    @property
    def from_addresses(self) -> list[str]:
        return [r.from_address for r in self.routes]

    @model_validator(mode="after")
    def final_validator(self) -> Self:
        if not self.private_keys.contains_all_addresses(self.from_addresses):
            raise ValueError("private keys are not set for all addresses")

        return self


class TransferErc20CmdParams(BaseConfigParams):
    print_balances: bool
    debug: bool
    no_receipt: bool
    emulate: bool


# noinspection DuplicatedCode
def run(cli_params: TransferErc20CmdParams) -> None:
    config = Config.read_toml_config_or_exit(cli_params.config_path)
    if cli_params.print_config_and_exit:
        config.print_and_exit({"private_keys"})

    mm_crypto_utils.init_logger(cli_params.debug, config.log_debug, config.log_info)
    rpc_helpers.check_nodes_for_chain_id(config.nodes, config.chain_id)

    # check decimals
    res = erc20.get_decimals(config.nodes[0], config.token)
    if isinstance(res, Err):
        fatal(f"can't get token decimals: {res.err}")
    if res.ok != config.decimals:
        fatal(f"config.decimals is wrong: {config.decimals} != {res.ok}")

    if cli_params.print_balances:
        print_helpers.print_balances(
            config.nodes,
            config.from_addresses,
            token_address=config.token,
            token_decimals=config.decimals,
            round_ndigits=config.round_ndigits,
        )
        sys.exit(0)

    return _run_transfers(config, cli_params)


# noinspection DuplicatedCode
def _run_transfers(config: Config, cli_params: TransferErc20CmdParams) -> None:
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
def _transfer(route: TxRoute, config: Config, cli_params: TransferErc20CmdParams) -> None:
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
        to_address=config.token,
        data=erc20.encode_transfer_input_data(route.to_address, 1234),
        log_prefix=log_prefix,
    )
    if gas is None:
        return

    # get value
    value = rpc_helpers.calc_erc20_value_for_address(
        nodes=config.nodes,
        value_expression=config.value,
        wallet_address=route.from_address,
        token_address=config.token,
        decimals=config.decimals,
        log_prefix=log_prefix,
    )
    if value is None:
        return

    # value_min_limit
    if config.value_min_limit is not None:
        value_min_limit = mm_crypto_utils.calc_int_expression(config.value_min_limit, suffix_decimals={"t": config.decimals})
        if value < value_min_limit:
            value_str = from_wei_str(value, "t", config.round_ndigits, decimals=config.decimals)
            logger.info(f"{log_prefix}value<value_min_limit, value={value_str}")
            return

    priority_fee = calc_eth_expression(config.priority_fee)

    # emulate?
    if cli_params.emulate:
        msg = f"{log_prefix}: emulate,"
        msg += f" value={from_wei_str(value, 't', decimals=config.decimals, round_ndigits=config.round_ndigits)},"
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
    signed_tx = erc20.sign_transfer_tx(
        nonce=nonce,
        max_fee_per_gas=max_fee,
        max_priority_fee_per_gas=priority_fee,
        gas_limit=gas,
        private_key=config.private_keys[route.from_address],
        chain_id=config.chain_id,
        value=value,
        token_address=config.token,
        recipient_address=route.to_address,
    )
    res = rpc.eth_send_raw_transaction(config.nodes, signed_tx.raw_tx, attempts=5)
    if isinstance(res, Err):
        logger.info(f"{log_prefix}: send_error: {res.err}")
        return
    tx_hash = res.ok

    if cli_params.no_receipt:
        msg = f"{log_prefix}: tx_hash={tx_hash}, value={from_wei_str(value, 't', decimals=config.decimals, round_ndigits=config.round_ndigits)}"  # noqa: E501
        logger.info(msg)
    else:
        logger.debug(f"{log_prefix}: tx_hash={tx_hash}, wait receipt")
        while True:  # TODO: infinite loop if receipt_res is err
            receipt_res = rpc.get_tx_status(config.nodes, tx_hash)
            if isinstance(receipt_res, Ok):
                status = "OK" if receipt_res.ok == 1 else "FAIL"
                msg = f"{log_prefix}: tx_hash={tx_hash}, value={from_wei_str(value, 't', decimals=config.decimals, round_ndigits=config.round_ndigits)}, status={status}"  # noqa: E501
                logger.info(msg)
                break
            time.sleep(1)
