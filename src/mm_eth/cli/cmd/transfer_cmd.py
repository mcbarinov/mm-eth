import sys
import time
from pathlib import Path
from typing import Annotated, Self

import mm_crypto_utils
from loguru import logger
from mm_crypto_utils import AddressToPrivate, Transfer
from mm_std import BaseConfig, Err, fatal, utc_now
from pydantic import AfterValidator, BeforeValidator, Field, model_validator
from rich.console import Console
from rich.live import Live
from rich.table import Table

from mm_eth import erc20, rpc
from mm_eth.cli import calcs, cli_utils, rpc_helpers
from mm_eth.cli.calcs import calc_eth_expression
from mm_eth.cli.cli_utils import BaseConfigParams
from mm_eth.cli.validators import Validators
from mm_eth.tx import sign_tx
from mm_eth.utils import from_wei_str


class Config(BaseConfig):
    nodes: Annotated[list[str], BeforeValidator(Validators.nodes())]
    chain_id: int
    transfers: Annotated[list[Transfer], BeforeValidator(Validators.eth_transfers())]
    private_keys: Annotated[AddressToPrivate, BeforeValidator(Validators.eth_private_keys())]
    token: Annotated[str | None, AfterValidator(Validators.eth_address())] = None  # if None, then eth transfer
    token_decimals: int = -1
    max_fee: Annotated[str, AfterValidator(Validators.valid_eth_expression("base_fee"))]
    priority_fee: Annotated[str, AfterValidator(Validators.valid_eth_expression())]
    max_fee_limit: Annotated[str | None, AfterValidator(Validators.valid_eth_expression())] = None
    default_value: Annotated[str | None, AfterValidator(Validators.valid_eth_or_token_expression("balance"))] = None
    value_min_limit: Annotated[str | None, AfterValidator(Validators.valid_eth_or_token_expression())] = None
    gas: Annotated[str, AfterValidator(Validators.valid_eth_expression("estimate"))]
    delay: Annotated[str | None, AfterValidator(Validators.valid_calc_decimal_value())] = None  # in seconds
    round_ndigits: int = 5
    proxies: Annotated[list[str], Field(default_factory=list), BeforeValidator(Validators.proxies())]
    wait_tx_timeout: int = 120
    log_debug: Annotated[Path | None, BeforeValidator(Validators.log_file())] = None
    log_info: Annotated[Path | None, BeforeValidator(Validators.log_file())] = None

    @property
    def from_addresses(self) -> list[str]:
        return [r.from_address for r in self.transfers]

    @model_validator(mode="after")
    def final_validator(self) -> Self:
        if not self.private_keys.contains_all_addresses(self.from_addresses):
            raise ValueError("private keys are not set for all addresses")

        for transfer in self.transfers:  # If value is not set for a transfer, then set it to the global value of the config.
            if not transfer.value and self.default_value:
                transfer.value = self.default_value
        for transfer in self.transfers:  # Check all transfers have a value.
            if not transfer.value:
                raise ValueError(f"{transfer.log_prefix}: value is not set")

        if self.token:
            if self.default_value:
                Validators.valid_token_expression("balance")(self.default_value)
            if self.value_min_limit:
                Validators.valid_token_expression()(self.value_min_limit)
        else:
            if self.default_value:
                Validators.valid_eth_expression("balance")(self.default_value)
            if self.value_min_limit:
                Validators.valid_eth_expression()(self.value_min_limit)

        if self.token:
            res = erc20.get_decimals(self.nodes, self.token, proxies=self.proxies, attempts=5)
            if isinstance(res, Err):
                fatal(f"can't get token decimals: {res.err}")
            self.token_decimals = res.ok

        return self


class TransferCmdParams(BaseConfigParams):
    print_balances: bool
    print_transfers: bool
    debug: bool
    skip_receipt: bool
    emulate: bool


def run(cmd_params: TransferCmdParams) -> None:
    config = Config.read_toml_config_or_exit(cmd_params.config_path)
    if cmd_params.print_config:
        cli_utils.print_config(config, exclude={"private_keys"}, count=None if cmd_params.debug else {"proxies"})
        sys.exit(0)

    rpc_helpers.check_nodes_for_chain_id(config.nodes, config.chain_id)

    if cmd_params.print_transfers:
        _print_transfers(config)
        sys.exit(0)

    if cmd_params.print_balances:
        _print_balances(config)
        sys.exit(0)

    _run_transfers(config, cmd_params)


def _run_transfers(config: Config, cmd_params: TransferCmdParams) -> None:
    mm_crypto_utils.init_logger(cmd_params.debug, config.log_debug, config.log_info)
    logger.info(f"transfer {cmd_params.config_path}: started at {utc_now()} UTC")
    logger.debug(f"config={config.model_dump(exclude={'private_keys'}) | {'version': cli_utils.get_version()}}")
    for i, transfer in enumerate(config.transfers):
        _transfer(transfer, config, cmd_params)
        if config.delay is not None and i < len(config.transfers) - 1:
            delay_value = mm_crypto_utils.calc_decimal_value(config.delay)
            logger.info(f"delay {delay_value} seconds")
            if not cmd_params.emulate:
                time.sleep(float(delay_value))
    logger.info(f"finished at {utc_now()} UTC")


def _transfer(t: Transfer, config: Config, cmd_params: TransferCmdParams) -> None:
    nonce = rpc_helpers.get_nonce(config.nodes, t.from_address, t.log_prefix)
    if nonce is None:
        return

    max_fee = rpc_helpers.calc_max_fee(config.nodes, config.max_fee, t.log_prefix)
    if max_fee is None:
        return

    if rpc_helpers.is_max_fee_limit_exceeded(max_fee, config.max_fee_limit, t.log_prefix):
        return

    gas = _calc_gas(t, config)
    if gas is None:
        return

    value = _calc_value(t, max_fee=max_fee, gas=gas, config=config)
    if value is None:
        return

    if not _check_value_min_limit(t, value, config):
        return

    priority_fee = calc_eth_expression(config.priority_fee)

    # emulate?
    if cmd_params.emulate:
        msg = f"{t.log_prefix}: emulate,"
        msg += f" value={_value_with_suffix(value, config)},"
        msg += f" max_fee={from_wei_str(max_fee, 'gwei', config.round_ndigits)},"
        msg += f" priority_fee={from_wei_str(priority_fee, 'gwei', config.round_ndigits)},"
        msg += f" gas={gas}"
        logger.info(msg)
        return

    tx_hash = _send_tx(transfer=t, nonce=nonce, max_fee=max_fee, priority_fee=priority_fee, gas=gas, value=value, config=config)
    if tx_hash is None:
        return

    status = "UNKNOWN"
    if not cmd_params.skip_receipt:
        logger.debug(f"{t.log_prefix}: waiting for receipt, tx_hash={tx_hash}")
        status = cli_utils.wait_tx_status(config.nodes, config.proxies, tx_hash, config.wait_tx_timeout)

    logger.info(f"{t.log_prefix}: tx_hash={tx_hash}, value={_value_with_suffix(value, config)},  status={status}")


def _calc_value(transfer: Transfer, max_fee: int, gas: int, config: Config) -> int | None:
    if config.token:
        return rpc_helpers.calc_erc20_value_for_address(
            nodes=config.nodes,
            value_expression=transfer.value,
            wallet_address=transfer.from_address,
            token_address=config.token,
            decimals=config.token_decimals,
            log_prefix=transfer.log_prefix,
        )
    return rpc_helpers.calc_eth_value_for_address(
        nodes=config.nodes,
        value_expression=transfer.value,
        address=transfer.from_address,
        gas=gas,
        max_fee=max_fee,
        log_prefix=transfer.log_prefix,
    )


def _check_value_min_limit(transfer: Transfer, value: int, config: Config) -> bool:
    """Returns False if the transfer should be skipped."""
    if config.value_min_limit:
        if config.token:
            value_min_limit = calcs.calc_token_expression(config.value_min_limit, config.token_decimals)
        else:
            value_min_limit = calcs.calc_eth_expression(config.value_min_limit)
        if value < value_min_limit:
            logger.info(f"{transfer.log_prefix}: value<value_min_limit, value={_value_with_suffix(value, config)}")
    return True


def _send_tx(
    *, transfer: Transfer, nonce: int, max_fee: int, priority_fee: int, gas: int, value: int, config: Config
) -> str | None:
    debug_tx_params = {
        "nonce": nonce,
        "max_fee": max_fee,
        "priority_fee": priority_fee,
        "gas": gas,
        "value": value,
        "to": transfer.to_address,
        "chain_id": config.chain_id,
    }
    logger.debug(f"{transfer.log_prefix}: tx_params={debug_tx_params}")

    if config.token:
        signed_tx = erc20.sign_transfer_tx(
            nonce=nonce,
            max_fee_per_gas=max_fee,
            max_priority_fee_per_gas=priority_fee,
            gas_limit=gas,
            private_key=config.private_keys[transfer.from_address],
            chain_id=config.chain_id,
            value=value,
            token_address=config.token,
            recipient_address=transfer.to_address,
        )
    else:
        signed_tx = sign_tx(
            nonce=nonce,
            max_fee_per_gas=max_fee,
            max_priority_fee_per_gas=priority_fee,
            gas=gas,
            private_key=config.private_keys[transfer.from_address],
            chain_id=config.chain_id,
            value=value,
            to=transfer.to_address,
        )
    res = rpc.eth_send_raw_transaction(config.nodes, signed_tx.raw_tx, attempts=5)
    if isinstance(res, Err):
        logger.info(f"{transfer.log_prefix}: tx error {res.err}")
        return None
    return res.ok


def _calc_gas(transfer: Transfer, config: Config) -> int | None:
    if config.token:
        return rpc_helpers.calc_gas(
            nodes=config.nodes,
            gas_expression=config.gas,
            from_address=transfer.from_address,
            to_address=config.token,
            data=erc20.encode_transfer_input_data(transfer.to_address, 1234),
            log_prefix=transfer.log_prefix,
        )
    return rpc_helpers.calc_gas(
        nodes=config.nodes,
        gas_expression=config.gas,
        from_address=transfer.from_address,
        to_address=transfer.to_address,
        value=123,
        log_prefix=transfer.log_prefix,
    )


def _print_transfers(config: Config) -> None:
    table = Table("n", "from_address", "to_address", "value", title="transfers")
    for count, transfer in enumerate(config.transfers, start=1):
        table.add_row(str(count), transfer.from_address, transfer.to_address, transfer.value)
    console = Console()
    console.print(table)


def _print_balances(config: Config) -> None:
    if config.token:
        headers = ["n", "from_address", "nonce", "eth", "t", "to_address", "nonce", "eth", "t"]
    else:
        headers = ["n", "from_address", "nonce", "eth", "to_address", "nonce", "eth"]
    table = Table(*headers, title="balances")
    with Live(table, refresh_per_second=0.5):
        for count, transfer in enumerate(config.transfers):
            from_nonce = _get_nonce_str(transfer.from_address, config)
            to_nonce = _get_nonce_str(transfer.to_address, config)

            from_eth_balance = _get_eth_balance_str(transfer.from_address, config)
            to_eth_balance = _get_eth_balance_str(transfer.to_address, config)

            from_token_balance = _get_token_balance_str(transfer.from_address, config) if config.token else ""
            to_token_balance = _get_token_balance_str(transfer.to_address, config) if config.token else ""

            if config.token:
                table.add_row(
                    str(count),
                    transfer.from_address,
                    from_nonce,
                    from_eth_balance,
                    from_token_balance,
                    transfer.to_address,
                    to_nonce,
                    to_eth_balance,
                    to_token_balance,
                )
            else:
                table.add_row(
                    str(count),
                    transfer.from_address,
                    from_nonce,
                    from_eth_balance,
                    transfer.to_address,
                    to_nonce,
                    to_eth_balance,
                )


def _get_nonce_str(address: str, config: Config) -> str:
    return str(rpc.eth_get_transaction_count(config.nodes, address, proxies=config.proxies, attempts=5).ok_or_err())


def _get_eth_balance_str(address: str, config: Config) -> str:
    return rpc.eth_get_balance(config.nodes, address, proxies=config.proxies, attempts=5).map_or_else(
        lambda err: err,
        lambda ok: from_wei_str(ok, "eth", config.round_ndigits),
    )


def _get_token_balance_str(address: str, config: Config) -> str:
    if not config.token:
        raise ValueError("token is not set")
    return erc20.get_balance(config.nodes, config.token, address, proxies=config.proxies, attempts=5).map_or_else(
        lambda err: err,
        lambda ok: from_wei_str(ok, "t", decimals=config.token_decimals, round_ndigits=config.round_ndigits),
    )


def _value_with_suffix(value: int, config: Config) -> str:
    if config.token:
        return from_wei_str(value, "t", config.round_ndigits, decimals=config.token_decimals)
    return from_wei_str(value, "eth", config.round_ndigits)
