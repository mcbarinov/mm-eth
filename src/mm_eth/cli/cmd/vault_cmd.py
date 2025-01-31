from pathlib import Path

import mm_crypto_utils
from mm_std import fatal, print_plain

from mm_eth import vault
from mm_eth.account import is_private_key


def run(keys_url: str, vault_token: str, keys_file: Path) -> None:
    private_keys = mm_crypto_utils.read_items_from_file(keys_file, is_private_key)
    if not private_keys:
        fatal("private keys not found")

    res = vault.set_keys_from_vault(keys_url, vault_token, private_keys)
    if res.is_ok() and res.ok is True:
        print_plain(f"saved {len(private_keys)} private keys to the vault")
    else:
        fatal(f"error: {res.err}")
