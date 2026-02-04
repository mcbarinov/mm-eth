"""Ethereum account generation, derivation, and key utilities."""

from dataclasses import dataclass

import eth_utils
from eth_account import Account
from eth_account.hdaccount import Mnemonic
from eth_account.signers.local import LocalAccount
from eth_account.types import Language
from eth_keys import KeyAPI
from mm_result import Result

Account.enable_unaudited_hdwallet_features()

key_api = KeyAPI()

# Default derivation path template for Ethereum HD wallets
DEFAULT_DERIVATION_PATH = "m/44'/60'/0'/0/{i}"


@dataclass
class DerivedAccount:
    """Represents an account derived from a mnemonic phrase."""

    index: int
    path: str
    address: str
    private_key: str


def generate_mnemonic(num_words: int = 24) -> str:
    """Generate a BIP39 mnemonic phrase in English."""
    mnemonic = Mnemonic(Language.ENGLISH)
    return mnemonic.generate(num_words=num_words)


def derive_accounts(mnemonic: str, passphrase: str, derivation_path: str, limit: int) -> list[DerivedAccount]:
    """Derive multiple Ethereum accounts from a mnemonic phrase."""
    if "{i}" not in derivation_path:
        raise ValueError("derivation_path must contain {i}, for example: " + DEFAULT_DERIVATION_PATH)

    result: list[DerivedAccount] = []
    for i in range(limit):
        path = derivation_path.replace("{i}", str(i))
        acc = Account.from_mnemonic(mnemonic, passphrase, path)
        private_key = acc.key.to_0x_hex().lower()
        result.append(DerivedAccount(i, path, acc.address, private_key))
    return result


def private_to_address(private_key: str, lower: bool = False) -> Result[str]:
    """Convert a private key to its corresponding Ethereum address."""
    try:
        acc: LocalAccount = Account.from_key(private_key)
        address = acc.address.lower() if lower else acc.address
        return Result.ok(address)
    except Exception as e:
        return Result.err(e)


def is_private_key(private_key: str) -> bool:
    """Check if a hex string is a valid Ethereum private key."""
    try:
        key_api.PrivateKey(eth_utils.decode_hex(private_key)).public_key.to_address()
        return True  # noqa: TRY300
    except Exception:
        return False
