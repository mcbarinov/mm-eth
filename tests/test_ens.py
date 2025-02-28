from mm_std import Ok

from mm_eth import ens


def test_get_name_exists(infura):
    address = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"
    assert ens.get_name(infura(), address) == Ok("vitalik.eth")


def test_get_name_non_exists(infura):
    address = "0x743997F620846ab4CE946CBe3f5e5b5c51921D6E"  # random empty address
    assert ens.get_name(infura(), address) == Ok(None)
