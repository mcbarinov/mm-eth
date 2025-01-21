from pathlib import Path
from typing import Any

from mm_std import print_json

from mm_eth.account import generate_accounts, generate_mnemonic


def run(mnemonic: str, passphrase: str, limit: int, print_path: bool, path_prefix: str, save_file: str) -> None:  # nosec
    result: dict[str, Any] = {}
    if not mnemonic:
        mnemonic = generate_mnemonic()
    result["mnemonic"] = mnemonic
    if passphrase:
        result["passphrase"] = passphrase
    result["accounts"] = []
    for acc in generate_accounts(mnemonic=mnemonic, passphrase=passphrase, limit=limit, path_prefix=path_prefix):
        new_account = {"address": acc.address, "private": acc.private_key}
        if print_path:
            new_account["path"] = acc.path
        result["accounts"].append(new_account)
    print_json(result)

    if save_file:
        data = [acc["address"] + "\t" + acc["private"] for acc in result["accounts"]]
        Path(save_file).write_text("\n".join(data) + "\n")
