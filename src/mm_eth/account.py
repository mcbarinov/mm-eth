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
    """
    Generates a BIP39 mnemonic phrase in English.

    Args:
        num_words (int): Number of words in the mnemonic (12, 15, 18, 21, or 24).

    Returns:
        str: Generated mnemonic phrase.
    """
    mnemonic = Mnemonic(Language.ENGLISH)
    return mnemonic.generate(num_words=num_words)


def derive_accounts(mnemonic: str, passphrase: str, derivation_path: str, limit: int) -> list[DerivedAccount]:
    """
    Derives multiple Ethereum accounts from a given mnemonic phrase.

    Args:
        mnemonic (str): BIP39 mnemonic phrase.
        passphrase (str): Optional BIP39 passphrase.
        derivation_path (str): Path template with '{i}' as index placeholder.
        limit (int): Number of accounts to derive.

    Raises:
        ValueError: If derivation_path does not contain '{i}'.

    Returns:
        list[DerivedAccount]: List of derived Ethereum accounts.
    """
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
    """
    Converts a private key to its corresponding Ethereum address.

    Args:
        private_key (str): Hex-encoded private key.
        lower (bool): Whether to return address in lowercase.

    Returns:
        Result[str]: Ok(address) or Err(exception) on failure.
    """
    try:
        acc: LocalAccount = Account.from_key(private_key)
        address = acc.address.lower() if lower else acc.address
        return Result.ok(address)
    except Exception as e:
        return Result.err(e)


def is_private_key(private_key: str) -> bool:
    """
    Checks if a given hex string is a valid Ethereum private key.

    Args:
        private_key (str): Hex-encoded private key.

    Returns:
        bool: True if valid, False otherwise.
    """
    try:
        key_api.PrivateKey(eth_utils.decode_hex(private_key)).public_key.to_address()
        return True  # noqa: TRY300
    except Exception:
        return False
