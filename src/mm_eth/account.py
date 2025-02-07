from dataclasses import dataclass

import eth_utils
from eth_account import Account
from eth_account.hdaccount import Mnemonic
from eth_account.signers.local import LocalAccount
from eth_account.types import Language
from eth_keys import KeyAPI
from eth_typing import ChecksumAddress
from eth_utils import decode_hex

Account.enable_unaudited_hdwallet_features()

key_api = KeyAPI()

DEFAULT_DERIVATION_PATH = "m/44'/60'/0'/0/{i}"


@dataclass
class DerivedAccount:
    index: int
    path: str
    address: str
    private_key: str


def to_checksum_address(address: str) -> ChecksumAddress:
    return eth_utils.to_checksum_address(address)


def generate_mnemonic(num_words: int = 24) -> str:
    mnemonic = Mnemonic(Language.ENGLISH)
    return mnemonic.generate(num_words=num_words)


def derive_accounts(mnemonic: str, passphrase: str, derivation_path: str, limit: int) -> list[DerivedAccount]:
    if "{i}" not in derivation_path:
        raise ValueError("derivation_path must contain {i}, for example: " + DEFAULT_DERIVATION_PATH)
    result: list[DerivedAccount] = []
    for i in range(limit):
        path = derivation_path.replace("{i}", str(i))
        acc = Account.from_mnemonic(mnemonic, passphrase, path)
        private_key = acc.key.to_0x_hex().lower()
        result.append(DerivedAccount(i, path, acc.address, private_key))
    return result


def address_from_private(private_key: str) -> str:
    """returns address in lower case"""
    acc: LocalAccount = Account.from_key(private_key)
    return acc.address.lower()


def private_to_address(private_key: str) -> str | None:
    """returns address in lower case"""
    try:
        return key_api.PrivateKey(decode_hex(private_key)).public_key.to_address().lower()
    except Exception:
        return None


def is_private_key(private_key: str) -> bool:
    try:
        key_api.PrivateKey(decode_hex(private_key)).public_key.to_address()
        return True  # noqa: TRY300
    except Exception:
        return False


def is_address(address: str) -> bool:
    return eth_utils.is_address(address)
