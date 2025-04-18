import yaml
from mm_std import BaseConfig
from pydantic import StrictStr

from mm_eth import account, deploy, retry
from mm_eth.cli.cli_utils import BaseConfigParams


class Config(BaseConfig):
    private_key: StrictStr
    nonce: int | None = None
    gas: StrictStr
    max_fee_per_gas: str
    max_priority_fee_per_gas: str
    value: str | None = None
    contract_bin: StrictStr
    constructor_types: StrictStr = "[]"
    constructor_values: StrictStr = "[]"
    chain_id: int
    node: str


class DeployCmdParams(BaseConfigParams):
    broadcast: bool = False


async def run(cli_params: DeployCmdParams) -> None:
    config = Config.read_toml_config_or_exit(cli_params.config_path)
    if cli_params.print_config:
        config.print_and_exit({"private_key"})

    constructor_types = yaml.full_load(config.constructor_types)
    constructor_values = yaml.full_load(config.constructor_values)

    sender_address = account.private_to_address(config.private_key).unwrap()

    if config.nonce is None:
        config.nonce = (await retry.eth_get_transaction_count(5, config.node, None, address=sender_address)).unwrap(
            "can't get nonce"
        )

    deploy.get_deploy_contract_data(config.contract_bin, constructor_types, constructor_values)
