import asyncio
import sys
import time
from pathlib import Path
from typing import Annotated, Literal, Self, cast

from loguru import logger
from mm_std import utc_now
from mm_web3 import PrivateKeyMap, Transfer, Web3CliConfig, calc_decimal_expression, init_loguru
from pydantic import AfterValidator, BeforeValidator, Field, model_validator
from rich.console import Console
from rich.live import Live
from rich.table import Table

from mm_eth import converters, erc20, retry, tx
from mm_eth.cli import calcs, cli_utils
from mm_eth.cli.cli_utils import BaseConfigParams
from mm_eth.cli.validators import Validators
from mm_eth.converters import from_wei


class Config(Web3CliConfig):
    nodes: Annotated[list[str], BeforeValidator(Validators.nodes())]
    chain_id: int
    transfers: Annotated[list[Transfer], BeforeValidator(Validators.eth_transfers())]
    private_keys: Annotated[PrivateKeyMap, BeforeValidator(Validators.eth_private_keys())]
    token: Annotated[str | None, AfterValidator(Validators.eth_address())] = None  # if None, then eth transfer
    token_decimals: int = -1
    max_fee: Annotated[str, AfterValidator(Validators.valid_eth_expression("base_fee"))]
    priority_fee: Annotated[str, AfterValidator(Validators.valid_eth_expression())]
    max_fee_limit: Annotated[str | None, AfterValidator(Validators.valid_eth_expression())] = None
    default_value: Annotated[str | None, AfterValidator(Validators.valid_eth_or_token_expression("balance"))] = None
    value_min_limit: Annotated[str | None, AfterValidator(Validators.valid_eth_or_token_expression())] = None
    gas: Annotated[str, AfterValidator(Validators.valid_eth_expression("estimate"))]
    delay: Annotated[str | None, AfterValidator(Validators.decimal_expression())] = None  # in seconds
    round_ndigits: int = 5
    proxies: Annotated[list[str], Field(default_factory=list), BeforeValidator(Validators.proxies())]
    wait_tx_timeout: int = 120
    log_debug: Annotated[Path | None, BeforeValidator(Validators.log_file())] = None
    log_info: Annotated[Path | None, BeforeValidator(Validators.log_file())] = None

    @property
    def from_addresses(self) -> list[str]:
        return [r.from_address for r in self.transfers]

    @model_validator(mode="after")  # type:ignore[misc]
    async def final_validator(self) -> Self:
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
            self.token_decimals = (await retry.erc20_decimals(5, self.nodes, self.proxies, token=self.token)).unwrap(
                "can't get token decimals"
            )

        return self


class TransferCmdParams(BaseConfigParams):
    print_balances: bool
    print_transfers: bool
    debug: bool
    skip_receipt: bool
    emulate: bool


async def run(params: TransferCmdParams) -> None:
    config = await Config.read_toml_config_or_exit_async(params.config_path)
    if params.print_config:
        config.print_and_exit(exclude={"private_keys"})

    if params.print_transfers:
        _print_transfers(config)
        sys.exit(0)

    await cli_utils.check_nodes_for_chain_id(config.nodes, config.chain_id)

    if params.print_balances:
        await _print_balances(config)
        sys.exit(0)

    await _run_transfers(config, params)


async def _run_transfers(config: Config, cmd_params: TransferCmdParams) -> None:
    init_loguru(cmd_params.debug, config.log_debug, config.log_info)
    logger.info(f"transfer {cmd_params.config_path}: started at {utc_now()} UTC")
    logger.debug(f"config={config.model_dump(exclude={'private_keys'}) | {'version': cli_utils.get_version()}}")
    for i, transfer in enumerate(config.transfers):
        await _transfer(transfer, config, cmd_params)
        if config.delay is not None and i < len(config.transfers) - 1:
            delay_value = calc_decimal_expression(config.delay)
            logger.info(f"delay {delay_value} seconds")
            if not cmd_params.emulate:
                await asyncio.sleep(float(delay_value))
    logger.info(f"finished at {utc_now()} UTC")


async def _get_nonce(t: Transfer, config: Config) -> int | None:
    res = await retry.eth_get_transaction_count(5, config.nodes, config.proxies, address=t.from_address)
    if res.is_err():
        logger.error(f"{t.log_prefix}: nonce error: {res.unwrap_err()}")
        return None
    logger.debug(f"{t.log_prefix}: nonce={res.unwrap()}")
    return res.unwrap()


async def _calc_max_fee(t: Transfer, config: Config) -> int | None:
    if "base_fee" in config.max_fee.lower():
        base_fee_res = await retry.get_base_fee_per_gas(5, config.nodes, config.proxies)
        if base_fee_res.is_err():
            logger.error(f"{t.log_prefix}: base_fee error: {base_fee_res.unwrap_err()}")
            return None
        logger.debug(f"{t.log_prefix}: base_fee={base_fee_res.unwrap()}")
        return calcs.calc_eth_expression(config.max_fee, {"base_fee": base_fee_res.unwrap()})
    return calcs.calc_eth_expression(config.max_fee)


def check_max_fee_limit(t: Transfer, config: Config, max_fee: int) -> bool:
    if config.max_fee_limit:
        max_fee_limit = calcs.calc_eth_expression(config.max_fee_limit)
        if max_fee > max_fee_limit:
            msg = f"{t.log_prefix}: max_fee limit exceeded"
            msg += f", max_fee={from_wei(max_fee, 'gwei')}gwei, max_fee_limit={from_wei(max_fee_limit, 'gwei')}gwei"
            logger.error(msg)
            return False
    return True


async def _calc_gas(t: Transfer, config: Config) -> int | None:
    variables: dict[str, int] | None = None
    if "estimate" in config.gas.lower():
        if config.token:
            res = await retry.eth_estimate_gas(
                5,
                config.nodes,
                config.proxies,
                from_=t.from_address,
                to=config.token,
                data=erc20.encode_transfer_input_data(t.to_address, 12345),
            )
        else:
            res = await retry.eth_estimate_gas(
                5, config.nodes, config.proxies, from_=t.from_address, to=t.to_address, value=12345
            )
        if res.is_err():
            logger.error(f"{t.log_prefix}: gas estimate error: {res.unwrap_err()}")
            return None
        logger.debug(f"{t.log_prefix}: gas estimate={res.unwrap()}")
        variables = {"estimate": res.unwrap()}
    return calcs.calc_eth_expression(config.gas, variables)


async def _calc_eth_value(t: Transfer, max_fee: int, gas: int, config: Config) -> int | None:
    value_expression = t.value.lower()
    variables: dict[str, int] | None = None
    if "balance" in value_expression:
        res = await retry.eth_get_balance(5, config.nodes, config.proxies, address=t.from_address)
        if res.is_err():
            logger.error(f"{t.log_prefix}: balance error: {res.unwrap_err()}")
            return None
        logger.debug(f"{t.log_prefix}: balance={res.unwrap()}")
        variables = {"balance": res.unwrap()}

    value = calcs.calc_eth_expression(value_expression, variables)
    if "balance" in value_expression.lower():
        value = value - gas * max_fee
    return value


async def _calc_token_value(t: Transfer, config: Config) -> int | None:
    value_expression = t.value.lower()
    variables: dict[str, int] | None = None
    if "balance" in value_expression:
        res = await retry.erc20_balance(5, config.nodes, config.proxies, token=cast(str, config.token), wallet=t.from_address)
        if res.is_err():
            logger.error(f"{t.log_prefix}: balance error: {res.unwrap_err()}")
            return None
        logger.debug(f"{t.log_prefix}: balance={res.unwrap()}")
        variables = {"balance": res.unwrap()}
    return calcs.calc_token_expression(value_expression, config.token_decimals, variables)


async def _calc_value(t: Transfer, max_fee: int, gas: int, config: Config) -> int | None:
    if config.token:
        return await _calc_token_value(t, config)
    return await _calc_eth_value(t, max_fee, gas, config)


def _check_value_min_limit(t: Transfer, value: int, config: Config) -> bool:
    """Returns False if the transfer should be skipped."""
    if config.value_min_limit:
        if config.token:
            value_min_limit = calcs.calc_token_expression(config.value_min_limit, config.token_decimals)
        else:
            value_min_limit = calcs.calc_eth_expression(config.value_min_limit)
        if value < value_min_limit:
            logger.info(f"{t.log_prefix}: value<value_min_limit, value={_value_with_suffix(value, config)}")
    return True


async def _transfer(t: Transfer, config: Config, cmd_params: TransferCmdParams) -> None:
    nonce = await _get_nonce(t, config)
    if nonce is None:
        return

    max_fee = await _calc_max_fee(t, config)
    if max_fee is None:
        return

    if not check_max_fee_limit(t, config, max_fee):
        return

    gas = await _calc_gas(t, config)
    if gas is None:
        return

    value = await _calc_value(t, max_fee, gas, config)
    if value is None:
        return

    if not _check_value_min_limit(t, value, config):
        return

    priority_fee = calcs.calc_eth_expression(config.priority_fee)

    # emulate?
    if cmd_params.emulate:
        msg = f"{t.log_prefix}: emulate,"
        msg += f" value={_value_with_suffix(value, config)},"
        msg += f" max_fee={from_wei(max_fee, 'gwei', config.round_ndigits)}gwei,"
        msg += f" priority_fee={from_wei(priority_fee, 'gwei', config.round_ndigits)}gwei,"
        msg += f" gas={gas}"
        logger.info(msg)
        return

    tx_hash = await _send_tx(
        transfer=t, nonce=nonce, max_fee=max_fee, priority_fee=priority_fee, gas=gas, value=value, config=config
    )
    if tx_hash is None:
        return

    status = "UNKNOWN"
    if not cmd_params.skip_receipt:
        status = await wait_tx_status(t, tx_hash, config)

    logger.info(f"{t.log_prefix}: tx_hash={tx_hash}, value={_value_with_suffix(value, config)},  status={status}")


async def wait_tx_status(t: Transfer, tx_hash: str, config: Config) -> Literal["OK", "FAIL", "TIMEOUT"]:
    logger.debug(f"{t.log_prefix}: waiting for receipt, tx_hash={tx_hash}")
    started_at = time.perf_counter()
    count = 0
    while True:
        res = await retry.get_tx_status(5, config.nodes, config.proxies, tx_hash=tx_hash)
        logger.debug(f"{t.log_prefix}: status={res.value_or_error()}")
        if res.is_ok():
            return "OK" if res.unwrap() == 1 else "FAIL"

        await asyncio.sleep(1)
        count += 1
        if time.perf_counter() - started_at > config.wait_tx_timeout:
            return "TIMEOUT"


async def _send_tx(
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
        signed_tx = tx.sign_tx(
            nonce=nonce,
            max_fee_per_gas=max_fee,
            max_priority_fee_per_gas=priority_fee,
            gas=gas,
            private_key=config.private_keys[transfer.from_address],
            chain_id=config.chain_id,
            value=value,
            to=transfer.to_address,
        )
    res = await retry.eth_send_raw_transaction(5, config.nodes, config.proxies, raw_tx=signed_tx.raw_tx)
    if res.is_err():
        logger.error(f"{transfer.log_prefix}: send tx error={res.unwrap_err()}")
        return None
    logger.debug(f"{transfer.log_prefix}: tx_hash={res.unwrap()}")

    return res.unwrap()


def _print_transfers(config: Config) -> None:
    table = Table("n", "from_address", "to_address", "value", title="transfers")
    for count, transfer in enumerate(config.transfers, start=1):
        table.add_row(str(count), transfer.from_address, transfer.to_address, transfer.value)
    console = Console()
    console.print(table)


async def _print_balances(config: Config) -> None:
    if config.token:
        headers = ["n", "from_address", "nonce", "eth", "t", "to_address", "nonce", "eth", "t"]
    else:
        headers = ["n", "from_address", "nonce", "eth", "to_address", "nonce", "eth"]
    table = Table(*headers, title="balances")
    with Live(table, refresh_per_second=0.5):
        for count, transfer in enumerate(config.transfers):
            from_nonce = (
                await retry.eth_get_transaction_count(5, config.nodes, config.proxies, address=transfer.from_address)
            ).value_or_error()
            to_nonce = (
                await retry.eth_get_transaction_count(5, config.nodes, config.proxies, address=transfer.to_address)
            ).value_or_error()

            from_eth_balance = (
                (await retry.eth_get_balance(5, config.nodes, config.proxies, address=transfer.from_address))
                .map(lambda value: converters.from_wei(value, "ether", config.round_ndigits))
                .value_or_error()
            )

            to_eth_balance = (
                (await retry.eth_get_balance(5, config.nodes, config.proxies, address=transfer.to_address))
                .map(lambda value: converters.from_wei(value, "ether", config.round_ndigits))
                .value_or_error()
            )

            if config.token:
                from_token_balance = (
                    (await retry.erc20_balance(5, config.nodes, config.proxies, token=config.token, wallet=transfer.from_address))
                    .map(
                        lambda value: converters.from_wei(
                            value, "t", decimals=config.token_decimals, round_ndigits=config.round_ndigits
                        )
                    )
                    .value_or_error()
                )
                to_token_balance = (
                    (await retry.erc20_balance(5, config.nodes, config.proxies, token=config.token, wallet=transfer.to_address))
                    .map(
                        lambda value: converters.from_wei(
                            value, "t", decimals=config.token_decimals, round_ndigits=config.round_ndigits
                        )
                    )
                    .value_or_error()
                )
            else:
                from_token_balance = ""  # nosec
                to_token_balance = ""  # nosec

            if config.token:
                cli_utils.add_table_raw(
                    table,
                    count,
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
                cli_utils.add_table_raw(
                    table,
                    count,
                    transfer.from_address,
                    from_nonce,
                    from_eth_balance,
                    transfer.to_address,
                    to_nonce,
                    to_eth_balance,
                )


def _value_with_suffix(value: int, config: Config) -> str:
    if config.token:
        return f"{from_wei(value, 't', config.round_ndigits, decimals=config.token_decimals)}t"
    return f"{from_wei(value, 'eth', config.round_ndigits)}eth"
