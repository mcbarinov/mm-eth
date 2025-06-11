import mm_print

from mm_eth import account


def run(private_key: str) -> None:
    res = account.private_to_address(private_key)
    if res.is_ok():
        mm_print.plain(res.unwrap())
    else:
        mm_print.fatal(f"invalid private key: '{private_key}'")
