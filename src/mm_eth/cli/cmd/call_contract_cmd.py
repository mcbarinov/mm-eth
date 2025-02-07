import json
from logging import fatal

from mm_std import BaseConfig, Err, print_plain
from pydantic import StrictStr

from mm_eth import abi, rpc
from mm_eth.cli.cli_utils import BaseConfigParams


class Config(BaseConfig):
    contract_address: StrictStr
    function_signature: str
    function_args: StrictStr = "[]"
    outputs_types: str | None = None
    node: str


class CallContractCmdParams(BaseConfigParams):
    pass


def run(cli_params: CallContractCmdParams) -> None:
    config = Config.read_toml_config_or_exit(cli_params.config_path)
    if cli_params.print_config:
        config.print_and_exit()

    input_data = abi.encode_function_input_by_signature(
        config.function_signature,
        json.loads(config.function_args.replace("'", '"')),
    )
    res = rpc.eth_call(config.node, config.contract_address, input_data)
    if isinstance(res, Err):
        return fatal(f"error: {res.err}")

    result = res.ok
    if config.outputs_types is not None:
        decode_res = abi.decode_data(_get_types(config.outputs_types), result)
        result = decode_res[0] if len(decode_res) == 1 else str(decode_res)
    print_plain(result)


def _get_types(data: str) -> list[str]:
    return [t.strip() for t in data.split(",") if t.strip()]
