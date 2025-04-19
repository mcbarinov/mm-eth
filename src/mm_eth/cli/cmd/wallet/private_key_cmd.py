from mm_std import fatal, print_plain

from mm_eth import account


def run(private_key: str) -> None:
    res = account.private_to_address(private_key)
    if res.is_ok():
        print_plain(res.unwrap())
    else:
        fatal(f"invalid private key: '{private_key}'")
