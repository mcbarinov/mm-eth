"""CLI command: compile Solidity contracts."""

import json
from pathlib import Path

from mm_print import print_json, print_plain

from mm_eth.cli.cli import PrintFormat
from mm_eth.cli.cli_utils import fatal
from mm_eth.solc import solc


def run(contract_path: Path, tmp_dir: Path, print_format: PrintFormat) -> None:
    """Compile a Solidity file and print the ABI and bytecode."""
    contract_name = contract_path.stem
    res = solc(contract_name, contract_path, tmp_dir)
    if res.is_err():
        fatal(res.unwrap_err())

    bin_ = res.unwrap().bin
    abi = res.unwrap().abi

    if print_format == PrintFormat.JSON:
        print_json({"bin": bin_, "abi": json.loads(abi)})
    else:
        print_plain("bin:")
        print_plain(bin_)
        print_plain("abi:")
        print_plain(abi)
