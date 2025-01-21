import sys
import time
from pathlib import Path
from typing import Self

from loguru import logger
from mm_std import BaseConfig, Err, Ok, print_json, str_to_list, utc_now
from pydantic import Field, StrictStr, field_validator, model_validator

from mm_eth import rpc
from mm_eth.account import create_private_keys_dict, private_to_address
from mm_eth.cli import calcs, cli_utils, print_helpers, rpc_helpers, validators
from mm_eth.tx import sign_tx
from mm_eth.utils import from_wei_str


class Config(BaseConfig):
    class Tx(BaseConfig):
        from_address: str
        to_address: str

    nodes: list[StrictStr]
    chain_id: int
    private_keys: dict[str, str] = Field(default_factory=dict)
    private_keys_file: str | None = None
    max_fee_per_gas: str
    max_fee_per_gas_limit: str | None = None
    max_priority_fee_per_gas: str
    value: str
    value_min_limit: str | None = None
    gas: str
    addresses_map: str | None = None
    addresses_from_file: str | None = None
    addresses_to_file: str | None = None
    delay: str | None = None  # in seconds
    round_ndigits: int = 5
    log_debug: str | None = None
    log_info: str | None = None
    txs: list[Tx] = Field(default_factory=list)

    @property
    def from_addresses(self) -> list[str]:
        return [tx.from_address for tx in self.txs]

    @field_validator("log_debug", "log_info", mode="before")
    @classmethod
    def log_validator(cls, v: str | None) -> str | None:
        return validators.log_validator(v)

    @field_validator("nodes", mode="before")
    @classmethod
    def nodes_validator(cls, v: str | list[str] | None) -> list[str]:
        return validators.nodes_validator(v)

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
        if not validators.is_valid_calc_var_wei_value(self.value, "balance"):
            raise ValueError(f"wrong value: {self.value}")

        # value_min_limit
        if not validators.is_valid_calc_var_wei_value(self.value_min_limit):
            raise ValueError(f"wrong value_min_limit: {self.value_min_limit}")

        # gas
        if not validators.is_valid_calc_var_wei_value(self.gas, "estimate"):
            raise ValueError(f"wrong gas: {self.gas}")

        # delay
        if not validators.is_valid_calc_decimal_value(self.delay):
            raise ValueError(f"wrong delay: {self.delay}")

        # txs
        if self.addresses_map:
            for tx in cli_utils.load_tx_addresses_from_str(self.addresses_map):
                self.txs.append(Config.Tx(from_address=tx[0], to_address=tx[1]))
        if self.addresses_from_file and self.addresses_to_file:
            self.txs.extend(
                Config.Tx(from_address=tx[0], to_address=tx[1])
                for tx in cli_utils.load_tx_addresses_from_files(self.addresses_from_file, self.addresses_to_file)
            )
        if not self.txs:
            raise ValueError("txs is empty")

        return self


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
        print_json(config.model_dump(exclude={"private_key", "addresses_map"}))
        sys.exit(0)

    cli_utils.init_logger(debug, config.log_debug, config.log_info)
    rpc_helpers.check_nodes_for_chain_id(config.nodes, config.chain_id)

    if print_balances:
        print_helpers.print_balances(config.nodes, config.from_addresses, round_ndigits=config.round_ndigits)
        sys.exit(0)

    return _run_transfers(config, no_receipt=no_receipt, emulate=emulate)


# noinspection DuplicatedCode
def _run_transfers(config: Config, *, no_receipt: bool, emulate: bool) -> None:
    logger.info(f"started at {utc_now()} UTC")
    logger.debug(f"config={config.model_dump(exclude={'private_keys', 'addresses_map'}) | {'version': cli_utils.get_version()}}")
    cli_utils.check_private_keys(config.from_addresses, config.private_keys)
    for i, tx in enumerate(config.txs):
        _transfer(from_address=tx.from_address, to_address=tx.to_address, config=config, no_receipt=no_receipt, emulate=emulate)
        if not emulate and config.delay is not None and i < len(config.txs) - 1:
            delay_value = calcs.calc_decimal_value(config.delay)
            logger.debug(f"delay {delay_value} seconds")
            time.sleep(float(delay_value))
    logger.info(f"finished at {utc_now()} UTC")


# noinspection DuplicatedCode
def _transfer(*, from_address: str, to_address: str, config: Config, no_receipt: bool, emulate: bool) -> None:
    log_prefix = f"{from_address}->{to_address}"
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

    # get gas
    gas = rpc_helpers.calc_gas(
        nodes=config.nodes,
        gas=config.gas,
        from_address=from_address,
        to_address=to_address,
        value=123,
        log_prefix=log_prefix,
    )
    if gas is None:
        return

    # get value
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

    # value_min_limit
    if calcs.is_value_less_min_limit(config.value_min_limit, value, "eth", log_prefix=log_prefix):
        return

    max_priority_fee_per_gas = calcs.calc_var_wei_value(config.max_priority_fee_per_gas)
    tx_params = {
        "nonce": nonce,
        "max_fee_per_gas": max_fee_per_gas,
        "max_priority_fee_per_gas": max_priority_fee_per_gas,
        "gas": gas,
        "value": value,
        "to": to_address,
        "chain_id": config.chain_id,
    }

    # emulate?
    if emulate:
        msg = f"{log_prefix}: emulate, value={from_wei_str(value, 'eth', config.round_ndigits)},"
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
        to=to_address,
    )
    res = rpc.eth_send_raw_transaction(config.nodes, signed_tx.raw_tx, attempts=5)
    if isinstance(res, Err):
        logger.info(f"{log_prefix}: send_error: {res.err}")
        return
    tx_hash = res.ok

    if no_receipt:
        msg = f"{log_prefix}: tx_hash={tx_hash}, value={from_wei_str(value, 'ether', round_ndigits=config.round_ndigits)}"
        logger.info(msg)
    else:
        logger.debug(f"{log_prefix}: tx_hash={tx_hash}, wait receipt")
        while True:
            receipt_res = rpc.get_tx_status(config.nodes, tx_hash)
            if isinstance(receipt_res, Ok):
                status = "OK" if receipt_res.ok == 1 else "FAIL"
                msg = f"{log_prefix}: tx_hash={tx_hash}, value={from_wei_str(value, 'ether', round_ndigits=config.round_ndigits)}, status={status}"  # noqa: E501
                logger.info(msg)
                break
            time.sleep(1)
