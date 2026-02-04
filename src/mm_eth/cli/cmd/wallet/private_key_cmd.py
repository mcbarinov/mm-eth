"""CLI command: derive address from a private key."""

from mm_print import print_plain

from mm_eth import account
from mm_eth.cli.cli_utils import fatal


def run(private_key: str) -> None:
    """Print the Ethereum address for the given private key."""
    res = account.private_to_address(private_key)
    if res.is_ok():
        print_plain(res.unwrap())
    else:
        fatal(f"invalid private key: '{private_key}'")
