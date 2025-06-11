import json
from pathlib import Path

import mm_print

from mm_eth.cli.cli import PrintFormat
from mm_eth.solc import solc


def run(contract_path: Path, tmp_dir: Path, print_format: PrintFormat) -> None:
    contract_name = contract_path.stem
    res = solc(contract_name, contract_path, tmp_dir)
    if res.is_err():
        mm_print.fatal(res.unwrap_err())

    bin_ = res.unwrap().bin
    abi = res.unwrap().abi

    if print_format == PrintFormat.JSON:
        mm_print.json({"bin": bin_, "abi": json.loads(abi)})
    else:
        mm_print.plain("bin:")
        mm_print.plain(bin_)
        mm_print.plain("abi:")
        mm_print.plain(abi)
