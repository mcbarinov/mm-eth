from mm_eth import account
from mm_eth.account import DEFAULT_DERIVATION_PATH


def test_generate_mnemonic():
    assert len(account.generate_mnemonic().split()) == 24
    assert len(account.generate_mnemonic(12).split()) == 12
    assert account.generate_mnemonic() != account.generate_mnemonic()


def test_generate_accounts():
    mnemonic = "tuition skin amateur sail oak bone panel concert horse need panel balance"
    passphrase = "pass-secret"
    res = account.derive_accounts(mnemonic, passphrase, DEFAULT_DERIVATION_PATH, 7)
    assert len(res) == 7
    assert res[3].index == 3
    assert res[3].path == "m/44'/60'/0'/0/3"
    assert res[3].address == "0x2F9e1b9f4D11756E84d4b6D2f6B107FA37feB701"
    assert res[3].private_key == "0x7b222a59ac8496b4f1f623bc86d15e889af8406f796037888ddee1290b933183"


def test_to_checksum_address():
    address = "0x46246a9e6B931EE2C60a525455c01689bA8eb2Ae"
    assert account.to_checksum_address("0x46246a9e6b931ee2c60a525455c01689ba8eb2ae") == address


def test_private_to_address():
    address = "0x46246a9e6B931EE2C60a525455c01689bA8eb2Ae"
    assert account.private_to_address("0xbc2a0bb29ed04fd94cb413a4483e56187e6faf13c2f6f4ab4ec0fa5bef8fd128") == address.lower()
    assert account.private_to_address("123") is None


def test_is_private_key():
    assert account.is_private_key("0xd17e3e15fd28dea2825073d08ab8b7320555759e5639d889d7b4b314c49743a0")
    assert account.is_private_key("d17e3e15fd28dea2825073d08ab8b7320555759e5639d889d7b4b314c49743a0")
    assert not account.is_private_key("17e3e15fd28dea2825073d08ab8b7320555759e5639d889d7b4b314c49743a0")
    assert not account.is_private_key("d17e3e15fd28dea2825073d08ab8b7320555759e5639d889d7b4b314c49743a09999999")
    assert not account.is_private_key("qwe")
    assert not account.is_private_key("")
