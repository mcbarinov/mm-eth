from dataclasses import dataclass

import eth_utils
from eth_account import Account
from eth_account.hdaccount import Mnemonic
from eth_account.types import Language
from eth_keys import KeyAPI
from eth_typing import ChecksumAddress
from eth_utils import decode_hex

Account.enable_unaudited_hdwallet_features()

key_api = KeyAPI()


@dataclass
class NewAccount:
    path: str
    address: str
    private_key: str


def to_checksum_address(address: str) -> ChecksumAddress:
    return eth_utils.to_checksum_address(address)


def generate_mnemonic(num_words: int = 24) -> str:
    mnemonic = Mnemonic(Language.ENGLISH)
    return mnemonic.generate(num_words=num_words)


def generate_accounts(  # nosec
    mnemonic: str,
    passphrase: str = "",
    path_prefix: str = "m/44'/60'/0'/0",
    limit: int = 12,
) -> list[NewAccount]:
    result: list[NewAccount] = []
    for i in range(limit):
        path = f"{path_prefix}/{i}"
        acc = Account.from_mnemonic(mnemonic=mnemonic, account_path=path, passphrase=passphrase)
        private_key = acc.key.hex().lower()
        if not private_key.startswith("0x"):
            private_key = f"0x{private_key}"
        result.append(NewAccount(path, acc.address, private_key))
    return result


def private_to_address(private_key: str) -> str | None:
    """returns address in lower case"""
    try:
        return key_api.PrivateKey(decode_hex(private_key)).public_key.to_address().lower()
    except Exception:
        return None


def create_private_keys_dict(private_keys: list[str]) -> dict[str, str]:  # address in lower
    result = {}
    for private_key in private_keys:
        address = private_to_address(private_key)
        if address is None:
            raise ValueError("wrong private key")
        result[address.lower()] = private_key
    return result


def is_private_key(private_key: str) -> bool:
    try:
        key_api.PrivateKey(decode_hex(private_key)).public_key.to_address()
        return True  # noqa: TRY300
    except Exception:
        return False
