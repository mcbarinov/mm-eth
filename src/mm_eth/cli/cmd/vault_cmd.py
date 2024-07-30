from mm_std import fatal, print_plain

from mm_eth import vault
from mm_eth.cli import cli_utils


def run(keys_url: str, vault_token: str, keys_file: str) -> None:
    private_keys = cli_utils.load_private_keys_from_file(keys_file)
    if not private_keys:
        fatal("private keys not found")

    res = vault.set_keys_from_vault(keys_url, vault_token, private_keys)
    if res.is_ok() and res.ok is True:
        print_plain(f"saved {len(private_keys)} private keys to the vault")
    else:
        fatal(f"error: {res.err}")
