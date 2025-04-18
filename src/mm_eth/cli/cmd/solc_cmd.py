import json
from pathlib import Path

from mm_std import PrintFormat, fatal, print_json, print_plain
from mm_std.fs import get_filename_without_extension

from mm_eth.solc import solc


def run(contract_path: Path, tmp_dir: Path, print_format: PrintFormat) -> None:
    contract_name = get_filename_without_extension(contract_path)
    res = solc(contract_name, contract_path, tmp_dir)
    if res.is_err():
        fatal(res.unwrap_error())

    bin_ = res.unwrap().bin
    abi = res.unwrap().abi

    if print_format == PrintFormat.JSON:
        print_json({"bin": bin_, "abi": json.loads(abi)})
    else:
        print_plain("bin:")
        print_plain(bin_)
        print_plain("abi:")
        print_plain(abi)
